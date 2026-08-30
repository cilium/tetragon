# Windows smoke test for Tetragon.
#
# Starts Tetragon, lets each module under modules\ drive its own probes, and asserts
# that the matching events reach the JSON export. Exit code is the number of failed
# checks.
#
# What gets tested is exactly what modules\ contains: the modules are discovered by
# listing that directory, and each one contributes the Tetragon flags it needs, the
# readiness markers to wait for, its probes and its checks. A build that supports
# fewer features ships fewer module files and nothing else changes -- this file, and
# harness.ps1, are meant to be identical across Tetragon OSS and Tetragon Enterprise.
#
# "Tetragon" throughout means the Tetragon.exe process this script starts as an
# ordinary application -- not a Tetragon service, which the caller is expected to
# have stopped. At the end it is sent SIGINT so it unloads cleanly, never killed; see
# Stop-Tetragon in harness.ps1 for why. Only Tetragon.exe is managed here; the eBPF
# services are assumed to be installed and running.

[CmdletBinding()]
param(
    [string]$TetragonExe = 'C:\Program Files\Tetragon\cmd\Tetragon.exe',
    [string]$ExportFile = 'C:\Program Files\Tetragon\events.json',
    [string]$TetragonLog = 'C:\Program Files\Tetragon\tetragon.log',
    [string]$TetragonErrorLog = 'C:\Program Files\Tetragon\tetragon.err.log',

    # defaults.DefaultPidFile. Deleted along with the logs, because a Tetragon that
    # died without cleaning up leaves one behind and the next start then refuses with
    # "another Tetragon instance seems to be up and running" -- a false positive as
    # soon as the pid has been reused. Safe only because the run aborts first if a
    # Tetragon process actually exists, which is the stronger check.
    [string]$PidFile = 'C:\Program Files\Tetragon\tetragon.pid',

    # Run only these modules, by Name. Empty means every module in modules\. For
    # narrowing a failure down by hand; CI passes nothing.
    [string[]]$Modules = @(),

    [int]$ReadyTimeoutSeconds = 180,
    [int]$ProbeTimeoutSeconds = 60,
    [int]$EventTimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'harness.ps1')

# Logged last by observer.Start(), so it means sensors are loaded and the
# ring-buffer reader is up -- unlike the export file, which exists as soon as the
# exporter writes its first synthetic exec. Modules add their own markers on top.
$readyMarker = 'Listening for events...'

# Two binaries, two roles. $pwshExe is the harness's own, used for the processes the
# test starts for itself. $powershellExe is the subject: probes run under it because
# that is the binary the datapath enforces against and the one whose script blocks
# Tetragon subscribes to.
$pwshExe = (Get-Command 'pwsh.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $pwshExe) { throw 'pwsh.exe was not found on PATH' }
$powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# Read before Tetragon starts, so a failure here costs no run.
$expectedUid = Get-LogonLuid

$loaded = @()
$tetragon = $null
$stream = $null
try {
    # --- modules -------------------------------------------------------------

    $loaded = Import-SmokeModules -Path (Join-Path $PSScriptRoot 'modules') -Only $Modules -Seed @{
        Uid                 = $expectedUid
        HarnessPid          = $PID
        PowershellExe       = $powershellExe
        PwshExe             = $pwshExe
        ProbeTimeoutSeconds = $ProbeTimeoutSeconds
    }

    # Flags are unioned rather than concatenated: two modules may legitimately need
    # the same one, but two different values for it means the modules disagree about
    # how Tetragon should be configured, and silently picking one would make the run
    # meaningless.
    $flags = [ordered]@{}
    foreach ($mod in $loaded) {
        if (-not $mod.Flags) { continue }
        foreach ($flag in $mod.Flags.Keys) {
            if ($flags.Contains($flag) -and "$($flags[$flag])" -ne "$($mod.Flags[$flag])") {
                throw "modules disagree on $flag : '$($flags[$flag])' vs '$($mod.Flags[$flag])' (from $($mod.Name))"
            }
            $flags[$flag] = $mod.Flags[$flag]
        }
    }

    $tetragonArgs = @('--debug')
    foreach ($flag in $flags.Keys) {
        $value = $flags[$flag]
        if ($value -is [bool]) {
            if ($value) { $tetragonArgs += $flag }
        }
        else {
            $tetragonArgs += @($flag, "`"$value`"")
        }
    }
    $tetragonArgs += @('--export-filename', "`"$ExportFile`"")

    $readiness = @(@{ Stream = 'stdout'; Text = $readyMarker })
    foreach ($mod in $loaded) {
        foreach ($marker in @($mod.Ready)) {
            if ($marker) { $readiness += $marker }
        }
    }

    # --- tetragon ------------------------------------------------------------

    $running = Get-Process -Name 'Tetragon' -ErrorAction SilentlyContinue
    if ($running) {
        throw "Tetragon is already running (pid $($running.Id -join ', ')); stop it before running this test"
    }
    foreach ($stale in $ExportFile, $TetragonLog, $TetragonErrorLog, $PidFile) {
        if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
    }

    Start-LogGroup 'tetragon startup'
    Write-Host "tetragon: $TetragonExe"
    Write-Host "modules: $(($loaded | ForEach-Object { $_.Name }) -join ', ')"
    Write-Host "flags: $($tetragonArgs -join ' ')"
    Write-Host "uid: $expectedUid"
    # Its own console rather than -NoNewWindow, so the SIGINT in Stop-Tetragon cannot
    # reach this script. Both streams therefore have to go to files.
    $tetragon = Start-Process -FilePath $TetragonExe `
        -WorkingDirectory (Split-Path -Parent $TetragonExe) `
        -RedirectStandardOutput $TetragonLog `
        -RedirectStandardError $TetragonErrorLog `
        -WindowStyle Hidden -PassThru `
        -ArgumentList $tetragonArgs

    foreach ($marker in $readiness) {
        $log = if ($marker.Stream -eq 'stderr') { $TetragonErrorLog } else { $TetragonLog }
        Wait-Until -TimeoutSeconds $ReadyTimeoutSeconds -What "'$($marker.Text)' in $log" -Condition {
            if ($tetragon.HasExited) { throw "Tetragon exited with code $($tetragon.ExitCode); see $TetragonLog" }
            (Test-Path -LiteralPath $log) -and
            (Select-String -LiteralPath $log -SimpleMatch $marker.Text -Quiet)
        }
        Write-Host "tetragon: saw '$($marker.Text)'"
    }
    Write-Host "tetragon: ready (pid $($tetragon.Id))"
    Stop-LogGroup

    # Take the export position before the probes run, so only their events are
    # parsed. History before this point cannot contain them.
    Wait-Until -TimeoutSeconds $ReadyTimeoutSeconds -What "$ExportFile to be created" -Condition {
        Test-Path -LiteralPath $ExportFile
    }
    $stream = [System.IO.FileStream]::new(
        $ExportFile,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    $stream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null

    # --- probes --------------------------------------------------------------

    Start-LogGroup 'probes'
    foreach ($mod in $loaded) {
        if ($mod.Probe) { & $mod.Probe $mod.S }
    }
    Stop-LogGroup

    # --- expectations --------------------------------------------------------

    # Built after the probes so the predicates can read pids from the module state.
    # Names are qualified with the module so two modules can use the same short name
    # and the report still says which one failed.
    $expect = @()
    $forbid = @()
    $verify = @()
    foreach ($mod in $loaded) {
        if ($mod.Expect) {
            $table = & $mod.Expect $mod.S
            foreach ($name in $table.Keys) {
                $expect += @{
                    Qualified = "$($mod.Name)/$name"
                    Test      = $table[$name]
                    State     = $mod.S
                }
            }
        }
        if ($mod.Forbid) {
            $table = & $mod.Forbid $mod.S
            foreach ($name in $table.Keys) {
                $forbid += @{
                    Qualified = "$($mod.Name)/$name"
                    Test      = $table[$name].Test
                    Why       = $table[$name].Why
                    State     = $mod.S
                    Violated  = $false
                }
            }
        }
        if ($mod.Verify) {
            foreach ($check in @(& $mod.Verify $mod.S)) {
                $verify += @{
                    Qualified = "$($mod.Name)/$($check.Name)"
                    Failures  = [int]$check.Failures
                    Detail    = $check.Detail
                    Why       = $check.Why
                }
            }
        }
    }

    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($check in $expect) { $pending.Add($check) }

    # --- match ---------------------------------------------------------------

    Start-LogGroup 'events'
    Write-Host "events: reading $ExportFile"
    try {
        Wait-ForEvents -Stream $stream -Pending $pending -Forbid $forbid -TimeoutSeconds $EventTimeoutSeconds
    }
    finally {
        $stream.Dispose()
    }
    Stop-LogGroup

    # --- report --------------------------------------------------------------

    $failures = 0

    Write-Host ''
    # If Tetragon died mid-test, every check below fails for that one reason. It is
    # reported as a warning rather than a failure because it is not itself a check.
    if ($tetragon.HasExited) {
        Write-Host "WARNING: Tetragon exited during the test with code $($tetragon.ExitCode); see $TetragonLog"
        Write-Annotation -Kind warning -Title 'smoke-test tetragon' -Message (
            "Tetragon exited during the test with code $($tetragon.ExitCode). " +
            "Every event check fails for that one reason; see $TetragonLog."
        )
    }
    Write-Host 'results'
    foreach ($check in $expect) {
        if ($pending.Contains($check)) {
            Write-Host "  FAIL $($check.Qualified)"
            Write-Annotation -Title "smoke-test $($check.Qualified)" -Message (
                "No event matching $($check.Qualified) reached $ExportFile within " +
                "${EventTimeoutSeconds}s of the probes finishing. Every field in the " +
                'predicate has to match; the uploaded events.json says which did not.'
            )
            $failures++
        }
        else {
            Write-Host "  ok   $($check.Qualified)"
        }
    }

    foreach ($check in $forbid) {
        if ($check.Violated) {
            Write-Host "  FAIL $($check.Qualified) (an event that must not exist was exported)"
            Write-Annotation -Title "smoke-test $($check.Qualified)" -Message $check.Why
            $failures++
        }
        else {
            Write-Host "  ok   $($check.Qualified)"
        }
    }

    foreach ($check in $verify) {
        if ($check.Failures -gt 0) {
            Write-Host "  FAIL $($check.Qualified) ($($check.Detail))"
            Write-Annotation -Title "smoke-test $($check.Qualified)" -Message $check.Why
            $failures += $check.Failures
        }
        else {
            Write-Host "  ok   $($check.Qualified)"
        }
    }

    Write-Host ''
    if ($failures -eq 0) {
        Write-Host "all $($expect.Count + $forbid.Count + $verify.Count) checks passed"
    }
    else {
        Write-Host "$failures check(s) failed"
    }
    exit $failures
}
catch {
    # A failed pwsh step gets no annotation of its own, and a readiness timeout is
    # the likeliest CI failure. Close the group first or the message lands inside a
    # collapsed one.
    Stop-LogGroup
    Write-Annotation -Title 'smoke-test' -Message $_.Exception.Message
    throw
}
finally {
    # Dispose is idempotent, so this covers both the normal path and a throw before
    # the match loop's own finally was reached.
    if ($stream) { $stream.Dispose() }
    foreach ($mod in $loaded) {
        foreach ($p in @($mod.S.Probes)) {
            if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    Stop-Tetragon -Tetragon $tetragon -PwshExe $pwshExe
}
