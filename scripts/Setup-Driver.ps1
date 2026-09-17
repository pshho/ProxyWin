[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$directory = Join-Path $root 'driver'
$hashes = @{
    'WinDivert.dll' = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
    'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
$valid = $true
foreach ($name in $hashes.Keys) {
    $path = Join-Path $directory $name
    if (-not (Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$name]) { $valid = $false }
}
if ($valid -and (Test-Path (Join-Path $directory 'LICENSE'))) {
    if ((Get-AuthenticodeSignature (Join-Path $directory 'WinDivert64.sys')).Status -ne 'Valid') { throw 'Driver signature is not valid.' }
    Write-Host 'WinDivert 2.2.2 x64 hashes and driver signature verified.'
    return
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('ProxyWin-driver-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $archive = Join-Path $temporary 'driver.zip'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $archive
    if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15') { throw 'Archive SHA-256 mismatch.' }
    Expand-Archive -LiteralPath $archive -DestinationPath $temporary
    $source = Join-Path $temporary 'WinDivert-2.2.2-A'
    foreach ($name in $hashes.Keys) {
        if ((Get-FileHash (Join-Path $source "x64/$name") -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$name]) { throw 'Binary SHA-256 mismatch.' }
    }
    if ((Get-AuthenticodeSignature (Join-Path $source 'x64/WinDivert64.sys')).Status -ne 'Valid') { throw 'Driver signature is not valid.' }
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    foreach ($name in $hashes.Keys) { Copy-Item -LiteralPath (Join-Path $source "x64/$name") -Destination (Join-Path $directory $name) }
    Copy-Item -LiteralPath (Join-Path $source 'LICENSE') -Destination (Join-Path $directory 'LICENSE')
    Write-Host 'WinDivert 2.2.2 x64 installed; hashes and signature verified.'
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
