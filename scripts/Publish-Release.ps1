[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Commit,
    [Parameter(Mandatory)][string]$Repository
)
$ErrorActionPreference = 'Stop'
if ($Version -cnotmatch '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$' -or
    $Commit -cnotmatch '^[a-f0-9]{40}$' -or $Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Invalid release identity.' }
function Invoke-Gh {
    param([string[]]$Arguments)
    $output = & gh @Arguments
    if ($LASTEXITCODE -ne 0) { throw "GitHub command failed: $($Arguments[0])" }
    return $output
}
$main = Invoke-Gh -Arguments @('api', "repos/$Repository/git/ref/heads/main", '--jq', '.object.sha')
if ($main -ne $Commit) {
    Write-Host 'A newer main commit exists. Skip publishing this stale run.'
    return
}
$tag = "v$Version"
$directory = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts/release'
$zip = Join-Path $directory "ProxyWin-$Version-win-x64.zip"
$checksum = "$zip.sha256"
$expected = ((Get-Content $checksum -Raw).Trim() -split ' +')[0]
if ($expected -ne (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Release checksum mismatch.' }
$localTag = & git rev-parse --verify --quiet "refs/tags/$tag^{}"
if ($LASTEXITCODE -eq 0) {
    if ($localTag -ne $Commit) { throw 'Tag belongs to another commit; refusing to overwrite.' }
} else {
    if ($LASTEXITCODE -ne 1) { throw 'Cannot inspect the local tag.' }
    Invoke-Gh -Arguments @('api', '--method', 'POST', "repos/$Repository/git/refs", '-f', "ref=refs/tags/$tag", '-f', "sha=$Commit") | Out-Null
}
# Listing distinguishes an absent release from an API/network error.
$releaseJson = Invoke-Gh -Arguments @('api', '--paginate', '--slurp', "repos/$Repository/releases?per_page=100")
# gh cannot combine --slurp with --jq. Flatten its array of pages locally.
$pages = ConvertFrom-Json -InputObject ($releaseJson -join [Environment]::NewLine)
$existing = @(foreach ($page in $pages) {
    foreach ($release in $page) {
        if ($release.tag_name -ceq $tag) { $release }
    }
})
if ($existing.Count -gt 0 -and -not $existing[0].draft) {
    Write-Host "Already published: $($existing[0].html_url)"
    return
}
if ($existing.Count -eq 0) {
    Invoke-Gh -Arguments @('release', 'create', $tag, '--repo', $Repository, '--verify-tag', '--draft', '--generate-notes', '--title', "ProxyWin $Version", '--notes-file', (Join-Path $directory 'notes.md')) | Out-Null
}
Invoke-Gh -Arguments @('release', 'upload', $tag, $zip, $checksum, '--repo', $Repository, '--clobber') | Out-Null
Invoke-Gh -Arguments @('release', 'edit', $tag, '--repo', $Repository, '--draft=false', '--latest') | Out-Null
Write-Host "Published https://github.com/$Repository/releases/tag/$tag"
