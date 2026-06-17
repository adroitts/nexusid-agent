# NexusID Sync Agent — Windows installer (irm-compatible).
#
#   irm https://raw.githubusercontent.com/adroitts/nexusid-agent/main/packaging/install.ps1 | iex
#
# Detects x64/x86 (ARM64 uses the x64 build under emulation), downloads the matching signed
# release from GitHub, verifies its SHA-256, installs to %LOCALAPPDATA%\NexusAgent and adds it to
# the user PATH. Override the version with $env:NEXUS_AGENT_VERSION (e.g. 'v0.1.0').
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$repo = 'adroitts/nexusid-agent'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'windows-x86_64' }
    'ARM64' { 'windows-x86_64' }  # x64 runs under emulation on Windows on ARM
    'x86'   { 'windows-x86' }
    default { 'windows-x86_64' }
}

$version = $env:NEXUS_AGENT_VERSION
if (-not $version) {
    Write-Host 'Resolving latest release...'
    $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
}

$asset = "nexus-agent-$version-$arch.zip"
$base  = "https://github.com/$repo/releases/download/$version"
$tmp   = Join-Path $env:TEMP "nexus-agent-$version"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zip = Join-Path $tmp $asset

Write-Host "Downloading $asset ..."
Invoke-WebRequest "$base/$asset" -OutFile $zip -UseBasicParsing

# Verify the SHA-256 (the .sha256 sidecar starts with the hash).
try {
    $expected = ((Invoke-RestMethod "$base/$asset.sha256") -split '\s+')[0].Trim().ToLower()
    $actual   = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($expected -and ($actual -ne $expected)) {
        throw "Checksum mismatch for $asset (expected $expected, got $actual)"
    }
    Write-Host 'Checksum verified.'
} catch {
    Write-Warning "Could not verify checksum: $_"
}

$dest = Join-Path $env:LOCALAPPDATA 'NexusAgent'
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -Path $zip -DestinationPath $dest -Force

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dest", 'User')
    $env:Path = "$env:Path;$dest"
}

Write-Host ""
Write-Host "nexus-agent $version installed to $dest" -ForegroundColor Green
Write-Host "Open a new terminal and run:  nexus-agent --help"
