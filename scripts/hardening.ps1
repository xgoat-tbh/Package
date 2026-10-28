# Hardening script: Restrict ACLs using the asymmetric policy
# Primary ($env:LOCALAPPDATA): (OI)(CI)(M) so unelevated self-heal works.
# Anchor ($env:ProgramData): (OI)(CI)(RX) for standard users.

param(
    [string]$PrimaryPath = "$env:LOCALAPPDATA\Microsoft\WindowsUpdate",
    [string]$AnchorPath = "$env:ProgramData\Microsoft\WindowsUpdate"
)

Write-Host "Applying asymmetric ACL hardening..."

if (Test-Path $PrimaryPath) {
    try {
        & icacls "$PrimaryPath" /grant "*S-1-5-32-545:(OI)(CI)(M)" "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C /Q
        Write-Host "Primary ACL applied: $PrimaryPath (Users: Modify)"
    } catch {
        Write-Host "Failed applying primary ACL: $_"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin -and (Test-Path $AnchorPath)) {
    try {
        & icacls "$AnchorPath" /grant "*S-1-5-32-545:(OI)(CI)(RX)" "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C /Q
        Write-Host "Anchor ACL applied: $AnchorPath (Users: Read/Execute)"
    } catch {
        Write-Host "Failed applying anchor ACL: $_"
    }
}
