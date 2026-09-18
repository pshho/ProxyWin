[CmdletBinding()]
param(
    [ValidateRange(10, 3600)][int]$SoakSeconds = 600,
    [string]$OutputDirectory,
    [string]$AppPath,
    [switch]$ElevatedWorker
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root ('artifacts/whale-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$app = if ($AppPath) { [IO.Path]::GetFullPath($AppPath) } else { Join-Path $root 'src/ProxyWin.App/bin/Release/net10.0-windows/ProxyWin.exe' }
$test = Join-Path $root 'tests/ProxyWin.LiveTests/bin/Release/net10.0-windows/ProxyWin.LiveTests.exe'
$regression = Join-Path $root 'tests/ProxyWin.Tests/bin/Release/net10.0-windows/ProxyWin.Tests.exe'
$whale = Join-Path $env:ProgramFiles 'Naver/Naver Whale/Application/whale.exe'
foreach ($file in @($app, $test, $regression, $whale)) { if (-not (Test-Path -LiteralPath $file)) { throw "Missing $file. Build App, Tests and LiveTests first." } }
if (-not $ElevatedWorker) {
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -ElevatedWorker -SoakSeconds ' + $SoakSeconds + ' -OutputDirectory "' + $OutputDirectory + '" -AppPath "' + $app + '"'
    $worker = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -PassThru
    if (-not $worker.WaitForExit(($SoakSeconds + 420) * 1000)) { throw 'Test worker timed out; inspect its report.' }
    if ($worker.ExitCode -ne 0) { throw "Whale validation failed ($($worker.ExitCode)); see $OutputDirectory" }
    Write-Host "PASS: $OutputDirectory"
    exit 0
}
$started = Get-Date
try {
    ConvertTo-Json -InputObject @(Get-CimInstance Win32_SystemDriver | Where-Object Name -Like '*WinDivert*' | Select-Object Name, State, PathName) | Set-Content (Join-Path $OutputDirectory 'driver-before.json') -Encoding UTF8
    & $regression --driver --report (Join-Path $OutputDirectory 'driver-regressions.txt')
    if ($LASTEXITCODE -ne 0) { throw "Driver regressions failed ($LASTEXITCODE)" }
    & $test $app $whale $OutputDirectory $SoakSeconds
    if ($LASTEXITCODE -ne 0) { throw "Whale test failed ($LASTEXITCODE)" }
    'PASS' | Set-Content (Join-Path $OutputDirectory 'worker-result.txt') -Encoding UTF8
} catch {
    $_.ToString() | Set-Content (Join-Path $OutputDirectory 'worker-result.txt') -Encoding UTF8
    exit 1
} finally {
    ConvertTo-Json -InputObject @(Get-CimInstance Win32_SystemDriver | Where-Object Name -Like '*WinDivert*' | Select-Object Name, State, PathName) | Set-Content (Join-Path $OutputDirectory 'driver-after.json') -Encoding UTF8
    # Record only counts/IDs, not unrelated application messages or payloads.
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $started; Level = 1, 2 } -ErrorAction Stop | Group-Object ProviderName, Id | Select-Object Name, Count)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
        else { $events = @([pscustomobject]@{ QueryError = $_.Exception.GetType().Name }) }
    }
    $eventJson = ConvertTo-Json -InputObject $events
    if (-not $eventJson) { $eventJson = '[]' }
    Set-Content (Join-Path $OutputDirectory 'system-errors.json') -Value $eventJson -Encoding UTF8
}
