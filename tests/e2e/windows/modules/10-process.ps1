# process_exec and process_exit.
#
# The base sensor is all this needs, so it ships in every build of Tetragon for
# Windows and needs no flags.
#
# cmd.exe is the probe, not notepad: notepad is a Store-app stub on recent Windows, so
# its System32 path can exit by itself, which makes a Stop-Process on it race or throw.
# cmd.exe is on every SKU, needs no interactive desktop, and exits on its own, which
# this module's exit check requires.

@{
    Name = 'process'

    State = @{
        ProbeExe = (Join-Path $env:SystemRoot 'System32\cmd.exe')
    }

    Probe = { param($s)
        $p = Register-Probe -State $s -Process (Start-Process `
                -FilePath $s.ProbeExe -ArgumentList '/c', 'exit 0' -WindowStyle Hidden -PassThru)
        $s.Probe = $p

        Wait-Until -TimeoutSeconds $s.ProbeTimeoutSeconds -What 'the process probe to exit' -Condition {
            $p.HasExited
        }
        Write-Host "probe: $(Split-Path -Leaf $s.ProbeExe) pid $($p.Id) ran and exited"
    }

    Expect = { param($s)
        [ordered]@{
            'exec' = { param($ev, $s)
                $ev.process_exec -and
                $ev.process_exec.process.pid -eq $s.Probe.Id -and
                (Test-Binary $ev.process_exec.process.binary $s.ProbeExe) -and
                $ev.process_exec.process.uid -eq $s.Uid -and
                $ev.process_exec.parent.pid -eq $s.HarnessPid
            }
            'exit' = { param($ev, $s)
                $ev.process_exit -and
                $ev.process_exit.process.pid -eq $s.Probe.Id -and
                (Test-Binary $ev.process_exit.process.binary $s.ProbeExe) -and
                $ev.process_exit.process.uid -eq $s.Uid -and
                $ev.process_exit.parent.pid -eq $s.HarnessPid
            }
        }
    }
}
