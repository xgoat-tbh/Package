# Hardening script: Restrict ACLs on the install directory
# Grants full control to SYSTEM and Administrators, and read/execute only to standard Users.

param(
    [string]$Path = "$env:LOCALAPPDATA\Microsoft\WindowsUpdate"
)

if (-not (Test-Path $Path)) {
    Write-Host "Directory $Path does not exist."
    exit 0
}

Write-Host "Applying restrictive ACLs to $Path..."
try {
    # Disable inheritance and copy rules, or reset to SYSTEM and Administrators
    & icacls "$Path" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" /T /C /Q
    Write-Host "Hardening completed successfully."
} catch {
    Write-Host "Hardening failed: $_"
}
