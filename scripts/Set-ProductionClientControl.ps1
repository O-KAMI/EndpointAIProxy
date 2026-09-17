# Compatibility guard: installation is now managed by transactional MSI actions.
# This file carries no credentials and must never silently claim provisioning succeeded.
[CmdletBinding()]
param([string]$CredentialsFile, [switch]$SkipServiceRestart)
[Console]::Error.WriteLine('Use the 0.1.22 MSI through IOA. Configuration and rollback are managed by the windowless installer helper.')
exit 1603
