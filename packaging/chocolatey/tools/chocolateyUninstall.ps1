$ErrorActionPreference = 'Stop'
# Chocolatey removes the auto-generated shim and the package tools directory on uninstall;
# nothing extra to clean up for this portable CLI.
Write-Host 'nexus-agent uninstalled.'
