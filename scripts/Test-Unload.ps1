[CmdletBinding()]
param([string]$AppPath, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $AppPath) { $AppPath = Join-Path $root 'src/ProxyWin.App/bin/Release/net10.0-windows/ProxyWin.exe' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root ('artifacts/unload-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$test = Join-Path $root 'tests/ProxyWin.LiveTests/bin/Release/net10.0-windows/ProxyWin.LiveTests.exe'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$child = Start-Process $test -Verb RunAs -ArgumentList ('--unload "' + $AppPath + '" "' + $OutputDirectory + '"') -PassThru
if (-not $child.WaitForExit(150000)) { throw 'Unload test timed out; inspect the report.' }
if ($child.ExitCode -ne 0) { throw "Unload test failed ($($child.ExitCode)); see $OutputDirectory/result.txt" }
Write-Output "PASS: $OutputDirectory/result.txt"
