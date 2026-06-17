$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Templated by the release pipeline.
$version = '__VERSION__'
$base = "https://github.com/adroitts/nexusid-agent/releases/download/v$version"

# Downloads the signed zip for the host architecture, verifies its checksum, and unpacks into the
# package tools dir — Chocolatey auto-shims nexus-agent.exe onto PATH.
Install-ChocolateyZipPackage `
  -PackageName 'nexus-agent' `
  -Url        "$base/nexus-agent-v$version-windows-x86.zip" `
  -Url64bit   "$base/nexus-agent-v$version-windows-x86_64.zip" `
  -UnzipLocation $toolsDir `
  -Checksum   '__SHA256_X86__' -ChecksumType   'sha256' `
  -Checksum64 '__SHA256_X64__' -ChecksumType64 'sha256'
