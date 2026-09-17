[CmdletBinding()]
param([switch]$FrameworkDependent, [switch]$DriverTests, [string]$Version)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $Version) {
    [xml]$project = Get-Content (Join-Path $root 'src/ProxyWin.App/ProxyWin.App.csproj') -Raw
    $Version = $project.Project.PropertyGroup.Version
}
if ($Version -cnotmatch '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$') {
    throw 'Version must be major.minor.patch.'
}
& (Join-Path $PSScriptRoot 'Setup-Driver.ps1')
function Invoke-DotNet {
    param([string[]]$CommandArgs)
    if (Get-Command rtk -ErrorAction SilentlyContinue) { & rtk proxy dotnet @CommandArgs }
    else { & dotnet @CommandArgs }
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed ($LASTEXITCODE)" }
}
Invoke-DotNet -CommandArgs @('run', '--project', 'tests/ProxyWin.Tests/ProxyWin.Tests.csproj', '-c', 'Release', '--', '--report', 'artifacts/ci/unit.txt')
if ($DriverTests) { & (Join-Path $PSScriptRoot 'Test-Driver.ps1') }
$output = Join-Path $root "artifacts/ProxyWin-$Version-win-x64"
$selfContained = if ($FrameworkDependent) { 'false' } else { 'true' }
Invoke-DotNet -CommandArgs @('publish', 'src/ProxyWin.App/ProxyWin.App.csproj', '-c', 'Release', '-r', 'win-x64', '--self-contained', $selfContained, "-p:Version=$Version", '-o', $output)
Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $output
Copy-Item -LiteralPath (Join-Path $root 'THIRD-PARTY-NOTICES.md') -Destination $output
if (Test-Path (Join-Path $root 'VERIFICATION.md')) { Copy-Item -LiteralPath (Join-Path $root 'VERIFICATION.md') -Destination $output }
Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination $output -Recurse -Force
Write-Host "Ready: $output/ProxyWin.exe"
