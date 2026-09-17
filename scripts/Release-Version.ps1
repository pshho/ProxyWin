function Get-ReleaseVersion {
    param(
        [string[]]$Tags = @(),
        [string[]]$HeadTags = @(),
        [string]$BaseVersion = '0.5.0'
    )
    $pattern = '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$'
    if ($BaseVersion -cnotmatch $pattern) { throw 'BaseVersion must be major.minor.patch.' }
    $versions = @($Tags | Where-Object { $_ -cmatch ('^v' + $pattern.Substring(1)) } |
        ForEach-Object { [version]$_.Substring(1) } | Sort-Object -Descending)
    $existing = @($HeadTags | Where-Object { $_ -cin $Tags -and $_ -cmatch ('^v' + $pattern.Substring(1)) } |
        ForEach-Object { [version]$_.Substring(1) } | Sort-Object -Descending)
    if ($existing.Count -gt 0) { $selected = $existing[0] }
    elseif ($versions.Count -eq 0 -or [version]$BaseVersion -gt $versions[0]) { $selected = [version]$BaseVersion }
    else {
        $latest = $versions[0]
        $selected = [version]::new($latest.Major, $latest.Minor, $latest.Build + 1)
    }
    if ($selected.Major -gt 65534 -or $selected.Minor -gt 65534 -or $selected.Build -gt 65534) {
        throw 'Release version exceeds Windows assembly version limits. Bump the minor/major base version.'
    }
    return $selected.ToString(3)
}
