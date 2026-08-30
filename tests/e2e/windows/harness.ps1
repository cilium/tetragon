# Shared harness for the Windows smoke test.
#
# Dot-sourced by smoke-test.ps1. Everything here is independent of which Tetragon
# features are under test; the feature-specific parts live in modules\*.ps1.
#
# This file is meant to be byte-identical in Tetragon OSS and Tetragon Enterprise
# and copied between them verbatim, so nothing in it may name an Enterprise-only
# flag, event type, path or module.
#
# ---------------------------------------------------------------------------
# Module contract
# ---------------------------------------------------------------------------
#
# A module is a .ps1 under modules\ that returns one hashtable. Discovery is by
# directory listing, sorted by file name, so a repo ships a feature's checks by
# shipping its file and nothing else -- there is no manifest to keep in sync.
# Only 'Name' is required; unknown keys are a hard error, because a misspelled key
# would otherwise silently delete a check.
#
#   Name    [string]  short identifier, used to qualify check names in the report.
#
#   State   [hashtable]  the module's own constants: ports, urls, probe paths.
#           Merged over the seed the harness supplies (see New-SmokeState) into
#           the module's state object, referred to as $s below. This is the one place
#           a module's constants live, so a predicate and the probe that produces the
#           events it matches cannot drift apart.
#
#   Flags   [ordered hashtable]  Tetragon command-line flags this module needs.
#           $true means a bare switch, a string means flag + value. Unioned across
#           modules; two modules asking for the same flag with different values is
#           an error. A module that is not present contributes no flags, which is
#           how a build that does not know a flag never sees it.
#
#   Ready   [array of @{ Stream = 'stdout'|'stderr'; Text = '...' }]  extra log
#           markers to wait for before any probe runs.
#
#   Probe   [scriptblock] param($s)  start this module's activity and wait for it
#           to reach the state its expectations assume. Probes started through
#           Start-Probe are cleaned up automatically; anything else must call
#           Register-Probe.
#
#   Expect  [scriptblock] param($s) -> [ordered]@{ <name> = { param($ev, $s) } }
#           Events that must appear. Invoked after Probe, so a predicate can read
#           the probe pids from $s.
#
#   Forbid  [scriptblock] param($s) -> [ordered]@{ <name> = @{ Test = { param($ev, $s) }; Why = '...' } }
#           Events that must NOT appear. Evaluated on every parsed line of the same
#           single pass as Expect. An absence check is only sound if the same module
#           also expects an event that provably comes later in the stream.
#
#   Verify  [scriptblock] param($s) -> @( @{ Name = '...'; Failures = <int>; Detail = '...'; Why = '...' } )
#           Checks that are not about the event stream at all, e.g. a probe's exit
#           code. Failures is added to the run's failure count.
#
# Both $s and the state hashtables inside it are passed by reference, so a module
# mutates its own state and the harness sees it.
#
# Why predicates take ($ev, $s) rather than closing over module locals: a module file's
# scope is gone by the time the driver invokes anything the module returned, so a
# variable set at the file's top level reads back as $null from inside Probe or a
# predicate (measured, not assumed). Module state therefore has to arrive as an
# argument. Two things do survive: functions, because this file is dot-sourced into the
# driver, and $PSScriptRoot, which is bound to the scriptblock's own file rather than
# looked up -- so it is still the module's directory, not the driver's. Locals of a
# *live* invocation behave normally, so a scriptblock built inside Probe and passed to
# Wait-Until sees them.

# GitHub-specific output is gated on this so a dev-box run stays readable.
function Test-OnRunner {
    $env:GITHUB_ACTIONS -eq 'true'
}

function Start-LogGroup {
    param([string]$Name)

    if (Test-OnRunner) { Write-Host "::group::$Name" }
}

function Stop-LogGroup {
    # Harmless with no group open, which is what makes it safe to call from a catch
    # block -- an unclosed group would collapse the failure out of sight.
    if (Test-OnRunner) { Write-Host '::endgroup::' }
}

function Write-Annotation {
    param(
        [ValidateSet('error', 'warning')]
        [string]$Kind = 'error',
        [string]$Title,
        [string]$Message
    )

    if (-not (Test-OnRunner)) { return }
    # A raw newline would end the command, and % is itself the escape character, so
    # it has to go first.
    $escaped = $Message -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
    Write-Host "::$Kind title=$Title::$escaped"
}

function Wait-Until {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds,
        [string]$What
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "timed out after ${TimeoutSeconds}s waiting for $What"
}

# Tetragon lowercases binary paths in events, so every comparison has to be
# case-insensitive.
function Test-Binary {
    param([string]$Reported, [string]$Expected)
    $Reported -and ($Reported -ieq $Expected)
}

# Records a process the harness must not leave behind. Start-Probe does it itself.
function Register-Probe {
    param([hashtable]$State, [System.Diagnostics.Process]$Process)

    $State.Probes = @($State.Probes) + $Process
    $Process
}

# Run a probe script under the binary the datapath is expected to see. That is
# $State.PowershellExe -- Windows PowerShell, not pwsh -- because process selection
# and the script-block channel are both implemented against that binary.
function Start-Probe {
    param(
        [hashtable]$State,
        [string]$Script,
        [string[]]$ProbeArgs = @()
    )

    if (-not $Script) { $Script = $State.ProbeScript }
    if (-not $Script) {
        throw 'Start-Probe: no probe script; pass -Script or set ProbeScript in the module State'
    }

    # Start-Process joins ArgumentList with spaces without quoting, so any argument
    # holding a path has to arrive already quoted.
    $p = Start-Process -FilePath $State.PowershellExe -PassThru -ArgumentList (
        @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$Script`"") + $ProbeArgs
    )
    Register-Probe -State $State -Process $p
}

# The uid Tetragon reports for the processes under test. On Windows it is the token's
# AuthenticationId -- the logon session LUID, not a POSIX uid. Probes are the
# harness's children and inherit its token, so one value covers all of them.
function Get-LogonLuid {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TetragonToken {
    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] public struct TOKEN_STATISTICS { public LUID TokenId; public LUID AuthenticationId; }
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
}
'@

    $tokenQuery = 0x0008
    $tokenStatistics = 10

    $token = [System.IntPtr]::Zero
    if (-not [TetragonToken]::OpenProcessToken([TetragonToken]::GetCurrentProcess(), $tokenQuery, [ref]$token)) {
        throw "OpenProcessToken failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    try {
        # Size query first: the struct declared above is deliberately shorter than
        # the real one, and a short buffer is rejected outright (error 122).
        $size = 0
        [TetragonToken]::GetTokenInformation($token, $tokenStatistics, [System.IntPtr]::Zero, 0, [ref]$size) | Out-Null
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        try {
            if (-not [TetragonToken]::GetTokenInformation($token, $tokenStatistics, $buffer, $size, [ref]$size)) {
                throw "GetTokenInformation failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            $stats = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [System.Type][TetragonToken+TOKEN_STATISTICS])
            (([uint64]$stats.AuthenticationId.HighPart) -shl 32) -bor $stats.AuthenticationId.LowPart
        }
        finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
    }
    finally { [TetragonToken]::CloseHandle($token) | Out-Null }
}

# SIGINT, via the console Tetragon owns. Go maps CTRL_C_EVENT to os.Interrupt, so
# this is the only shutdown that makes Tetragon release its BPF pins. It is never
# killed: release-pinned-bpf runs only on a graceful exit, so after a force-kill the
# BPF programs stay pinned, stay attached and keep enforcing, and block every later
# start until the eBPF services are cycled. If it does not honour the signal it is
# left running instead, which needs no cycle.
#
# Attaching to that console requires detaching from the current one first, which is
# why the signal is sent from a throwaway child process rather than here: a script
# that frees its own console loses every line it prints afterwards when stdout is a
# terminal, and leaves the calling shell unable to run a native command ("The handle
# is invalid ... while getting the console mode"). A child detaches only itself, so
# an interactive run ends as cleanly as a CI one.
#
# Tetragon still needs a console of its own (see the driver's Start-Process): the
# event goes to every process in the console group, so a shared console would signal
# the harness too.
function Stop-Tetragon {
    param(
        [System.Diagnostics.Process]$Tetragon,
        [string]$PwshExe,
        [int]$TimeoutSeconds = 30
    )

    if (-not $Tetragon -or $Tetragon.HasExited) { return }

    # Exit codes carry the outcome back: 1 = could not attach, 2 = the event was
    # refused. Passed as -EncodedCommand, which removes all quoting of the script.
    $signal = @"
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TetragonConsole {
    [DllImport("kernel32.dll")] public static extern bool FreeConsole();
    [DllImport("kernel32.dll")] public static extern bool AttachConsole(uint pid);
    [DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint groupId);
}
'@
[TetragonConsole]::FreeConsole() | Out-Null
if (-not [TetragonConsole]::AttachConsole($($Tetragon.Id))) { exit 1 }
# The console is shared as of the attach above, so ignore the event raised below.
[TetragonConsole]::SetConsoleCtrlHandler([System.IntPtr]::Zero, `$true) | Out-Null
if (-not [TetragonConsole]::GenerateConsoleCtrlEvent(0, 0)) { exit 2 }  # 0 = CTRL_C_EVENT
exit 0
"@

    $signaller = Start-Process -FilePath $PwshExe -WindowStyle Hidden -PassThru -Wait `
        -ArgumentList @(
            '-NoProfile'
            '-EncodedCommand'
            [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($signal))
        )

    if ($signaller.ExitCode -ne 0) {
        Write-Host "tetragon: SIGINT could not be delivered (signaller exit $($signaller.ExitCode)); left running rather than killed"
        return
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while (-not $Tetragon.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }

    if ($Tetragon.HasExited) {
        Write-Host "tetragon: exited on SIGINT with code $($Tetragon.ExitCode)"
    }
    else {
        Write-Host "tetragon: still running ${TimeoutSeconds}s after SIGINT; left running (a kill would leave its BPF programs pinned)"
    }
}

# What every module's state starts as, before its own State is merged over it.
function New-SmokeState {
    param(
        [uint64]$Uid,
        [int]$HarnessPid,
        [string]$PowershellExe,
        [string]$PwshExe,
        [int]$ProbeTimeoutSeconds
    )

    @{
        Uid                 = $Uid
        HarnessPid          = $HarnessPid
        PowershellExe       = $PowershellExe
        PwshExe             = $PwshExe
        ProbeTimeoutSeconds = $ProbeTimeoutSeconds
        Probes              = @()
    }
}

$script:smokeModuleKeys = @('Name', 'State', 'Flags', 'Ready', 'Probe', 'Expect', 'Forbid', 'Verify')

function Import-SmokeModules {
    param(
        [string]$Path,
        [hashtable]$Seed,
        [string[]]$Only = @()
    )

    $files = @(Get-ChildItem -LiteralPath $Path -Filter '*.ps1' -File | Sort-Object Name)
    if (-not $files) { throw "no modules found in $Path" }

    $modules = @()
    foreach ($file in $files) {
        $mod = & $file.FullName
        if ($mod -isnot [System.Collections.IDictionary]) {
            throw "$($file.Name) did not return a module descriptor hashtable"
        }
        if (-not $mod.Name) { throw "$($file.Name) returned a descriptor with no Name" }
        foreach ($key in $mod.Keys) {
            if ($script:smokeModuleKeys -notcontains $key) {
                throw "$($file.Name) has unknown descriptor key '$key'; expected one of $($script:smokeModuleKeys -join ', ')"
            }
        }
        if ($Only.Count -gt 0 -and $Only -notcontains $mod.Name) { continue }

        $state = New-SmokeState -Uid $Seed.Uid -HarnessPid $Seed.HarnessPid `
            -PowershellExe $Seed.PowershellExe -PwshExe $Seed.PwshExe `
            -ProbeTimeoutSeconds $Seed.ProbeTimeoutSeconds
        if ($mod.State) {
            foreach ($key in $mod.State.Keys) { $state[$key] = $mod.State[$key] }
        }
        $mod['S'] = $state
        $modules += $mod
    }

    if ($Only.Count -gt 0) {
        $missing = @($Only | Where-Object { $modules.Name -notcontains $_ })
        if ($missing) { throw "no such module: $($missing -join ', ')" }
    }
    if (-not $modules) { throw "no modules selected" }
    $modules
}

# One pass over the export, from wherever $Stream is positioned. Removes each
# matched record from $Pending and marks any $Forbid record whose event appeared.
# Returns when $Pending is empty or the deadline passes -- so an absence check is
# only as strong as the presence checks that keep the loop reading.
function Wait-ForEvents {
    param(
        [System.IO.Stream]$Stream,
        [System.Collections.Generic.List[object]]$Pending,
        [object[]]$Forbid,
        [int]$TimeoutSeconds
    )

    $decoder = [System.Text.UTF8Encoding]::new($false).GetDecoder()
    $bytes = [byte[]]::new(64 * 1024)
    $chars = [char[]]::new($bytes.Length)
    $partial = ''
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ($Pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        $read = $Stream.Read($bytes, 0, $bytes.Length)
        if ($read -eq 0) {
            Start-Sleep -Milliseconds 200
            continue
        }
        # A decoder, not Encoding.GetString: a read can split a multi-byte character
        # and the decoder carries that state across calls.
        $partial += [string]::new($chars, 0, $decoder.GetChars($bytes, 0, $read, $chars, 0))

        # Every record is newline-terminated, and a reader can observe a prefix of
        # one, so only complete lines are parsed.
        while (($nl = $partial.IndexOf("`n")) -ge 0) {
            $line = $partial.Substring(0, $nl)
            $partial = $partial.Substring($nl + 1)

            $ev = $null
            try { $ev = ConvertFrom-Json -InputObject $line } catch { }
            if (-not $ev) { continue }

            foreach ($check in @($Pending)) {
                if (& $check.Test $ev $check.State) {
                    $Pending.Remove($check) | Out-Null
                    Write-Host "  matched $($check.Qualified)"
                }
            }
            foreach ($check in $Forbid) {
                if (-not $check.Violated -and (& $check.Test $ev $check.State)) {
                    $check.Violated = $true
                    Write-Host "  violated $($check.Qualified)"
                }
            }
        }
    }
}
