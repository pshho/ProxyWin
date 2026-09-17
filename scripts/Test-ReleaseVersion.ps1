$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Release-Version.ps1')
$cases = @(
    @{ Name = 'First release'; Tags = @(); Head = @(); Base = '0.5.0'; Expected = '0.5.0' },
    @{ Name = 'Next patch'; Tags = @('v0.5.0'); Head = @(); Base = '0.5.0'; Expected = '0.5.1' },
    @{ Name = 'Numeric sorting'; Tags = @('v0.5.9', 'v0.5.10', 'v0.4.99'); Head = @(); Base = '0.5.0'; Expected = '0.5.11' },
    @{ Name = 'Retry same commit'; Tags = @('v0.5.0', 'v0.5.1'); Head = @('v0.5.1'); Base = '0.5.0'; Expected = '0.5.1' },
    @{ Name = 'Ignore unrelated tags'; Tags = @('v0.5.0', 'v9.0.0-beta', 'backup', 'v01.0.0'); Head = @(); Base = '0.5.0'; Expected = '0.5.1' },
    @{ Name = 'Explicit minor bump'; Tags = @('v0.5.9'); Head = @(); Base = '0.6.0'; Expected = '0.6.0' },
    @{ Name = 'No phantom HEAD tag'; Tags = @('v0.5.0'); Head = @('v9.0.0'); Base = '0.5.0'; Expected = '0.5.1' }
)
foreach ($case in $cases) {
    $actual = Get-ReleaseVersion -Tags $case.Tags -HeadTags $case.Head -BaseVersion $case.Base
    if ($actual -ne $case.Expected) { throw "$($case.Name): expected $($case.Expected), got $actual" }
    Write-Host "PASS $($case.Name)"
}
foreach ($invalid in @('invalid', '0.5', '0.5.0-beta', '00.5.0')) {
    $rejected = $false
    try { Get-ReleaseVersion -BaseVersion $invalid | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted invalid base version: $invalid" }
}
$rejected = $false
try { Get-ReleaseVersion -Tags @('v0.5.65534') | Out-Null } catch { $rejected = $true }
if (-not $rejected) { throw 'Accepted a patch outside the assembly version range.' }
Write-Host 'PASS invalid versions and patch overflow rejected'
