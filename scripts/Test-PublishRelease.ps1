# No network calls: exercise the publisher's failure and retry paths with CLI stubs.
$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('ProxyWin-publish-test-' + [guid]::NewGuid().ToString('N'))
$global:proxyWinPublishState = [pscustomobject]@{ Commit = ('a' * 40); Scenario = ''; Calls = [Collections.Generic.List[string]]::new() }
function gh {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Command)
    $global:proxyWinPublishState.Calls.Add(($Command -join '|'))
    $global:LASTEXITCODE = 0
    if ($Command -contains 'repos/test/ProxyWin/git/ref/heads/main') {
        if ($global:proxyWinPublishState.Scenario -eq 'ApiFailure') { $global:LASTEXITCODE = 1; return }
        if ($global:proxyWinPublishState.Scenario -eq 'Stale') { return ('b' * 40) }
        return $global:proxyWinPublishState.Commit
    }
    if ($Command -contains 'repos/test/ProxyWin/releases?per_page=100') {
        if ($global:proxyWinPublishState.Scenario -eq 'Published') { return '[{"tag_name":"v0.5.1","draft":false,"html_url":"https://example.invalid/release"}]' }
        if ($global:proxyWinPublishState.Scenario -eq 'Draft') { return '[{"tag_name":"v0.5.1","draft":true,"html_url":"https://example.invalid/release"}]' }
        return '[]'
    }
    if ($Command[0] -eq 'release' -and $Command[1] -eq 'upload' -and $global:proxyWinPublishState.Scenario -eq 'UploadFailure') { $global:LASTEXITCODE = 1 }
}
function git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Command)
    $global:LASTEXITCODE = 0
    if ($global:proxyWinPublishState.Scenario -eq 'Fresh' -or $global:proxyWinPublishState.Scenario -eq 'UploadFailure') { $global:LASTEXITCODE = 1; return }
    if ($global:proxyWinPublishState.Scenario -eq 'Conflict') { return ('c' * 40) }
    return $global:proxyWinPublishState.Commit
}
try {
    New-Item -ItemType Directory -Path "$fixture/scripts", "$fixture/artifacts/release" -Force | Out-Null
    Copy-Item (Join-Path $PSScriptRoot 'Publish-Release.ps1') "$fixture/scripts/"
    $zip = "$fixture/artifacts/release/ProxyWin-0.5.1-win-x64.zip"
    Set-Content $zip 'test payload' -Encoding ascii
    Set-Content "$zip.sha256" ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() + '  ProxyWin-0.5.1-win-x64.zip') -Encoding ascii
    Set-Content "$fixture/artifacts/release/notes.md" 'Test release' -Encoding ascii
    foreach ($name in @('Fresh', 'Draft', 'Published', 'Stale', 'ApiFailure', 'Conflict', 'UploadFailure', 'BadChecksum')) {
        $global:proxyWinPublishState.Scenario = $name
        $global:proxyWinPublishState.Calls.Clear()
        if ($name -eq 'BadChecksum') { Set-Content "$zip.sha256" ('0' * 64) -Encoding ascii }
        $failure = $null
        try { & "$fixture/scripts/Publish-Release.ps1" -Version '0.5.1' -Commit $global:proxyWinPublishState.Commit -Repository 'test/ProxyWin' }
        catch { $failure = $_ }
        $expectFailure = $name -in @('ApiFailure', 'Conflict', 'UploadFailure', 'BadChecksum')
        if (($null -ne $failure) -ne $expectFailure) { throw "$name failure mismatch: $failure" }
        $published = @($global:proxyWinPublishState.Calls | Where-Object { $_ -like 'release|edit|*' }).Count -gt 0
        if ($published -ne ($name -in @('Fresh', 'Draft'))) { throw "$name published unexpectedly or missed publication." }
        if ($name -in @('Published', 'Stale', 'ApiFailure', 'Conflict', 'BadChecksum') -and
            @($global:proxyWinPublishState.Calls | Where-Object { $_ -like 'release|*' -or $_ -like '*|POST|*' }).Count -gt 0) { throw "$name wrote to GitHub." }
        if ($name -eq 'Draft' -and @($global:proxyWinPublishState.Calls | Where-Object { $_ -like 'release|create|*' }).Count -gt 0) { throw 'Draft retry created another release.' }
        Write-Host "PASS publisher $name"
    }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
    Remove-Variable -Name proxyWinPublishState -Scope Global
}
