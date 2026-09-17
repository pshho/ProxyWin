[CmdletBinding()]
param([Parameter(Mandatory)][string]$Version)
$ErrorActionPreference = 'Stop'
if ($Version -cnotmatch '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$') { throw 'Invalid release version.' }
$root = Split-Path -Parent $PSScriptRoot
$name = "ProxyWin-$Version-win-x64"
$folder = Join-Path $root "artifacts/$name"
$dll = Join-Path $folder 'ProxyWin.dll'
if ([Reflection.AssemblyName]::GetAssemblyName($dll).Version.ToString(3) -ne $Version) { throw 'Published assembly version differs from the release.' }
foreach ($file in @('ProxyWin.exe', 'coreclr.dll', 'driver/WinDivert.dll', 'driver/WinDivert64.sys', 'driver/LICENSE')) {
    if (-not (Test-Path (Join-Path $folder $file))) { throw "Missing release file: $file" }
}
$unit = Get-Content (Join-Path $root 'artifacts/ci/unit.txt') -Raw
$gui = Get-Content (Join-Path $root 'artifacts/ci/gui/result.txt') -Raw
$result = [regex]::Match($unit, '(?m)^([0-9]+)/([0-9]+) passed')
if (-not $result.Success -or $result.Groups[1].Value -ne $result.Groups[2].Value -or -not $gui.StartsWith('PASS:')) {
    throw 'Successful unit and GUI reports are required before packaging.'
}
$report = @"
# ProxyWin $Version CI verification

Commit: $env:GITHUB_SHA
Run: https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID

$($result.Value)
$gui

The build passed driver hash/signature checks, version-selection tests, local regression tests, self-contained publication and GUI smoke checks.
Administrator WinDivert interception and interactive caret tests are NOT run in hosted CI.
VERIFICATION.md and docs/verification/v0.5.0-* describe the historical 0.5.0 local checks, not this CI run.
"@
Set-Content (Join-Path $folder 'CI-VERIFICATION.md') $report -Encoding utf8
$destination = Join-Path $root 'artifacts/release'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$zip = Join-Path $destination "$name.zip"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [IO.File]::Create($zip)
$archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $folder -File -Recurse -Force) {
        # Use ZIP-standard separators even in Windows PowerShell 5.1.
        $relative = $file.FullName.Substring($folder.Length + 1).Replace([char]92, [char]47)
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, "$name/$relative", [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose(); $stream.Dispose() }
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    foreach ($required in @('ProxyWin.exe', 'ProxyWin.dll', 'CI-VERIFICATION.md', 'docs/images/main.png')) {
        if ($null -eq $archive.GetEntry("$name/$required")) { throw "Missing ZIP entry: $required" }
    }
} finally { $archive.Dispose() }
$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content "$zip.sha256" "$hash  $name.zip" -Encoding ascii
Set-Content (Join-Path $destination 'notes.md') @"
Windows x64 self-contained release. Extract the entire ZIP and run ProxyWin.exe as administrator.

Version: $Version
Source: $env:GITHUB_SHA
CI: https://github.com/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID

Checks passed: release version tests, driver hash/signature verification, $($result.Value), Windows build and published GUI smoke checks.
Hosted CI does not test administrator WinDivert interception or interactive keyboard/caret behavior. See CI-VERIFICATION.md inside the archive for the exact scope.
"@ -Encoding utf8
Write-Host "Packaged $name.zip SHA256 $hash"
