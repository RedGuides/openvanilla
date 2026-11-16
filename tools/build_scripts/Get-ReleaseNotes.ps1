<#
.SYNOPSIS
    Generates the build manifest and release notes for Very Vanilla MQ

.DESCRIPTION
    The manifest records the commit that was built for:
    - MacroQuest (this repository)
    - eqlib
    - Each plugin repository that produced a DLL

    The release notes compare the manifest against the one from the previous release and list:
    - New CHANGELOG.md entries (or MacroQuest commits if the changelog is unchanged)
    - eqlib commits
    - Plugin commits, + added or removed

    Commits are only listed for public GitHub repositories. Any other plugin is listed as updated.

.PARAMETER Mode
    Manifest -> outputs the manifest for this build as JSON.
    Notes    -> outputs the release notes as markdown (nothing if there is nothing to report).

.PARAMETER Previous
    Path to the directory containing build-manifest.json and CHANGELOG.md from the previous release.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("Manifest", "Notes")][string]$Mode,
    [string]$Previous,
    [string]$Headline,
    [string]$MQRoot = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$pluginsDirectory = "$MQRoot\plugins"
$eqlibDirectory = "$MQRoot\src\eqlib"
$releasePluginsDirectory = "$MQRoot\build\bin\Release\plugins"
$changelogFile = "$MQRoot\data\resources\CHANGELOG.md"

# How many commits to list before "+N more"
$maxCommits = 10
$maxPluginCommits = 3

if ($env:RUNNER_DEBUG -eq "1") {
    $DebugPreference = "Continue"
}

# Use UTF-8 for command output so that we don't mangle strings that aren't ASCII
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Get-RepoChanges {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$OldCommit,
        [Parameter(Mandatory)][string]$NewCommit
    )

    # If the previous release didn't have this repository, then no reason to continue
    if ([string]::IsNullOrWhiteSpace($OldCommit)) {
        Write-Debug "Skipping commits for $Directory because there is no previous commit"
        return
    }

    # Read the URL from the config, and skip repositories that aren't on GitHub
    $repoUrl = (git -C $Directory config --get remote.origin.url) -replace '\.git$', ""
    if ($repoUrl -notmatch '^https://github\.com/[\w.-]+/[\w.-]+$') {
        Write-Debug "Skipping commits for $Directory because it is not hosted on GitHub"
        return
    }
    $repoName = $repoUrl -replace '^https://github\.com/', ""

    # Private repositories should not have their commits listed. The build token can't see other private repositories, so those fail here too.
    $isPrivate = gh api "repos/$repoName" --jq '.private' 2>$null
    if ($LASTEXITCODE -ne 0 -or $isPrivate -ne "false") {
        Write-Debug "Skipping commits for $Directory because it is not public"
        return
    }

    # Get the commits from GitHub so that it doesn't matter how much history the clone has (core and eqlib are shallow in CI)
    $commitLog = gh api "repos/$repoName/compare/$OldCommit...$NewCommit" --jq '.commits | reverse | .[] | select(.parents | length < 2) | .commit.message | split("\n")[0]'
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not get commits for $Directory ($OldCommit to $NewCommit) - they will be left out of the release notes."
        return
    }

    $subjects = @()
    foreach ($line in $commitLog) {
        # Ignore the commit that the live build makes to advance eqlib
        if ($line -notmatch '^eqlib: advance') {
            # Strip the PR number (trim first, some messages have a carriage return after it)
            $subject = $line.Trim() -replace '\s*\(#\d+\)$', ""
            # Strip a leading list marker, the subject is already going in a list
            $subject = $subject -replace '^[-*+]\s+', ""
            if ($subject.Length -gt 100) {
                $subject = $subject.Substring(0, 97) + "..."
            }
            if ($subject -ne "") {
                # Escape markdown so that the subject is shown as it was written (URLs are left alone, escaping would break the link)
                $subject = $subject -replace '(?<!https?://\S*)([\\`*_\[\]<>|])', '\$1'
                # GitHub would still link #123 (to an issue in this repository), a zero-width space after the # stops that.
                # Only do this at the start of a word, inside a URL it would break the link. @name is left alone so that it links.
                $subject = $subject -replace '(?<![\w/])#(?=\w)', "#$([char]0x200B)"
                # RedGuides would read [b] or [URL=...] as a tag, the same space after every bracket stops that (URLs are left alone)
                $subject = $subject -replace '(?<!https?://\S*)\[', "[$([char]0x200B)"
                $subjects += $subject
            }
        }
    }

    if ($subjects.Count -eq 0) {
        Write-Debug "Skipping commits for $Directory because there are none to list"
        return
    }

    return [PSCustomObject]@{
        Subjects = $subjects
        CompareUrl = "$repoUrl/compare/$($OldCommit.Substring(0, 7))...$($NewCommit.Substring(0, 7))"
    }
}

function Get-CommitSection {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Directory,
        [string]$OldCommit,
        [Parameter(Mandatory)][string]$NewCommit
    )

    $section = ""
    if ($OldCommit -ne $NewCommit) {
        $changes = Get-RepoChanges -Directory $Directory -OldCommit $OldCommit -NewCommit $NewCommit
        if ($changes) {
            $lines = @("## $Title", "")
            foreach ($subject in ($changes.Subjects | Select-Object -First $maxCommits)) {
                $lines += "- $subject"
            }
            if ($changes.Subjects.Count -gt $maxCommits) {
                $lines += "- [+$($changes.Subjects.Count - $maxCommits) more]($($changes.CompareUrl))"
            }
            $section = $lines -join "`n"
        }
    }
    return $section
}

# If the build output is not there, then no reason to continue
foreach ($directory in @($pluginsDirectory, $eqlibDirectory, $releasePluginsDirectory)) {
    if (-not (Test-Path -Path $directory -PathType Container)) {
        throw "Get-ReleaseNotes: required directory '$directory' not found. The manifest is built from the release output, so the build must complete first."
    }
}

if ($Mode -eq "Notes") {
    if ([string]::IsNullOrWhiteSpace($Previous)) {
        throw "Get-ReleaseNotes: -Previous is required for Notes mode."
    }
    if (-not (Test-Path -Path $changelogFile -PathType Leaf)) {
        throw "Get-ReleaseNotes: changelog not found: $changelogFile"
    }
}

$coreCommit = git -C $MQRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) {
    throw "Get-ReleaseNotes: could not get the MacroQuest commit from '$MQRoot'. The next release would compare against the wrong commit."
}

$eqlibCommit = git -C $eqlibDirectory rev-parse HEAD
if ($LASTEXITCODE -ne 0) {
    throw "Get-ReleaseNotes: could not get the eqlib commit from '$eqlibDirectory'. The next release would compare against the wrong commit."
}

# Plugins are cloned for all clients, but not all of them are built for this one. Only include a plugin if one of its projects built a DLL.
$builtPlugins = @(Get-ChildItem -Path $releasePluginsDirectory -Filter "*.dll" | ForEach-Object { $_.BaseName })

$plugins = [ordered]@{}
foreach ($pluginDirectory in (Get-ChildItem -Path $pluginsDirectory -Directory | Sort-Object -Property Name)) {
    $pluginBuilt = $false
    foreach ($project in (Get-ChildItem -Path $pluginDirectory.FullName -Filter "*.vcxproj" -Recurse)) {
        if ($builtPlugins -contains $project.BaseName) {
            $pluginBuilt = $true
        }
    }

    # Skip folders that are not a git clone (git would report the MacroQuest commit for them)
    if ($pluginBuilt -and (Test-Path -Path "$($pluginDirectory.FullName)\.git")) {
        $pluginCommit = git -C $pluginDirectory.FullName rev-parse HEAD
        if ($LASTEXITCODE -ne 0) {
            throw "Get-ReleaseNotes: could not get the commit for plugin '$($pluginDirectory.Name)'. The next release would compare against the wrong commit."
        }
        $plugins[$pluginDirectory.Name] = $pluginCommit
    }
}

$manifest = [ordered]@{
    core = $coreCommit
    eqlib = $eqlibCommit
    plugins = $plugins
}

if ($Mode -eq "Manifest") {
    $manifest | ConvertTo-Json
    exit 0
}

$sections = @()
if (-not [string]::IsNullOrWhiteSpace($Headline)) {
    $sections += $Headline.Trim()
}

# Load the manifest from the previous release (if there is one)
$previousManifest = $null
$previousManifestFile = "$Previous\build-manifest.json"
if (Test-Path -Path $previousManifestFile -PathType Leaf) {
    try {
        $previousManifest = Get-Content -Path $previousManifestFile -Raw | ConvertFrom-Json -AsHashtable
    } catch {
        $previousManifest = $null
    }
    if ($previousManifest -isnot [hashtable]) {
        Write-Warning "Could not read the previous manifest: $previousManifestFile - release notes will not include commits."
        $previousManifest = $null
    }
} else {
    Write-Host "No manifest from the previous release - release notes will not include commits."
}

# New changelog entries are everything above the first heading that the previous release already had
$changelogEntries = ""
$previousChangelogFile = "$Previous\CHANGELOG.md"
if (Test-Path -Path $previousChangelogFile -PathType Leaf) {
    $previousHeadings = @(Get-Content -Path $previousChangelogFile | Where-Object { $_ -match '^##\s' } | ForEach-Object { $_.Trim() })
    $newLines = @()
    foreach ($line in (Get-Content -Path $changelogFile)) {
        if ($line -match '^##\s' -and $previousHeadings -contains $line.Trim()) {
            break
        }
        $newLines += $line
    }
    $changelogEntries = ($newLines -join "`n").Trim()
}

if ($changelogEntries -ne "") {
    Write-Host "Found new changelog content."
    $sections += $changelogEntries
} else {
    Write-Host "Changelog unchanged since last release."
}

if ($previousManifest) {
    # The headline and changelog are always posted, so if anything fails here we just leave out the commits
    try {
        # The changelog is written for users, so if it has new entries we use those instead of the MacroQuest commits
        if ($changelogEntries -eq "") {
            $sections += Get-CommitSection -Title "MacroQuest" -Directory $MQRoot -OldCommit $previousManifest.core -NewCommit $coreCommit
        }

        $sections += Get-CommitSection -Title "EQ client (eqlib)" -Directory $eqlibDirectory -OldCommit $previousManifest.eqlib -NewCommit $eqlibCommit

        # Copy the previous plugins into a new table so that their names are compared without case
        $previousPlugins = @{}
        if ($previousManifest.plugins -is [hashtable]) {
            foreach ($pluginName in $previousManifest.plugins.Keys) {
                $previousPlugins[$pluginName] = $previousManifest.plugins[$pluginName]
            }
        }

        # Check each plugin against the previous release
        $pluginLines = @()
        $updatedPlugins = @()
        $addedPlugins = @()
        $removedPlugins = @()
        foreach ($pluginName in $plugins.Keys) {
            if (-not $previousPlugins.Contains($pluginName)) {
                $addedPlugins += $pluginName
            } elseif ($previousPlugins[$pluginName] -ne $plugins[$pluginName]) {
                $changes = Get-RepoChanges -Directory "$pluginsDirectory\$pluginName" -OldCommit $previousPlugins[$pluginName] -NewCommit $plugins[$pluginName]
                if ($changes) {
                    $pluginLine = "- [$pluginName]($($changes.CompareUrl)): " + (($changes.Subjects | Select-Object -First $maxPluginCommits) -join "; ")
                    if ($changes.Subjects.Count -gt $maxPluginCommits) {
                        $pluginLine += " (+$($changes.Subjects.Count - $maxPluginCommits) more)"
                    }
                    $pluginLines += $pluginLine
                } else {
                    # No commits to show, so this one is only listed by name
                    $updatedPlugins += $pluginName
                }
            }
        }
        foreach ($pluginName in ($previousPlugins.Keys | Sort-Object)) {
            if (-not $plugins.Contains($pluginName)) {
                $removedPlugins += $pluginName
            }
        }

        if ($updatedPlugins.Count -gt 0) {
            $pluginLines += "- Updated: $($updatedPlugins -join ', ')"
        }
        if ($addedPlugins.Count -gt 0) {
            $pluginLines += "- Added: $($addedPlugins -join ', ')"
        }
        if ($removedPlugins.Count -gt 0) {
            $pluginLines += "- Removed: $($removedPlugins -join ', ')"
        }
        if ($pluginLines.Count -gt 0) {
            $sections += "## Plugins`n`n" + ($pluginLines -join "`n")
        }
    } catch {
        Write-Warning "Could not compare against the previous release - release notes will not include all commits. $_"
    }
}

# Output the notes (sections with nothing to report are empty)
($sections | Where-Object { $_ }) -join "`n`n"
exit 0
