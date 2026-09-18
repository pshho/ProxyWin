[CmdletBinding()]
param([switch]$UpdateOnly, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'tests/ProxyWin.Tests/bin/Release/net10.0-windows/ProxyWin.Tests.exe'
$report = if ($ReportPath) { [IO.Path]::GetFullPath($ReportPath) } else { Join-Path $root 'artifacts/driver-test-v05.txt' }
if (-not (Test-Path $exe)) { throw 'Build the test project first.' }
New-Item -ItemType Directory -Force -Path (Split-Path $report) | Out-Null
# The test plan only captures 203.0.113.10 at TCP 443/7443/7447/8443/9443 and UDP 53/443/7444/7445,
# plus reverse traffic from its own temporary relay listeners. No route changes.
# A lower-priority test sink consumes DIRECT test datagrams so they do not leave the host.
# The metadata-only FLOW observer test is restricted to the test host's own PID.
# Wildcard tests select TCP/UDP 7446 and match only ProxyWin.Tests.exe.
# Update-only coverage uses TCP 7447 and a documentation-IP sink; no packets leave the host.
# As in normal operation, fragments cannot be port-filtered and are also captured.
# They send to 203.0.113.10/.11; a lower-priority sink prevents direct test egress.
$mode = if ($UpdateOnly) { '--driver-update' } else { '--driver' }
$arguments = $mode + ' --report "' + $report + '"'
$child = Start-Process -FilePath $exe -Verb RunAs -ArgumentList $arguments -PassThru
if (-not $child.WaitForExit(90000)) { throw 'Elevated test is still running; inspect the report and test window.' }
if (Get-Command rtk -ErrorAction SilentlyContinue) { & rtk read $report } else { Get-Content -LiteralPath $report -Encoding UTF8 }
if ($child.ExitCode -ne 0) { throw "Driver tests failed ($($child.ExitCode)); see $report" }
