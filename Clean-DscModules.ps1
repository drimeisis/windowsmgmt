# Clean-DscModules.ps1

$ModulesToClean = @(
    "SecurityPolicyDsc",
    "AuditPolicyDsc",
    "GPRegistryPolicyDsc",
    "NetworkingDsc",
    "GuestConfiguration"
)

Write-Host "--- STEP 1: Uninstalling all versions ---" -ForegroundColor Yellow

foreach ($Name in $ModulesToClean) {
    # Check if module exists
    $Versions = Get-Module -ListAvailable -Name $Name
    
    if ($Versions) {
        Write-Host "Found $($Versions.Count) versions of $Name. Removing..."
        
        # We use a loop because Uninstall-Module sometimes fails to remove all at once
        foreach ($v in $Versions) {
            try {
                Uninstall-Module -Name $Name -RequiredVersion $v.Version -Force -ErrorAction Stop
                Write-Host "  - Removed $Name ($($v.Version))" -ForegroundColor Green
            }
            catch {
                Write-Warning "  ! Could not remove $Name ($($v.Version)). It might be in use. Close other PS windows."
            }
        }
    }
    else {
        Write-Host "$Name is already clean."
    }
}

Write-Host "`n--- STEP 2: Installing Fresh Versions ---" -ForegroundColor Yellow

# Install fresh copies of the modules required for Server 2025 Baseline
Install-Module -Name SecurityPolicyDsc -Force -AllowClobber
Install-Module -Name AuditPolicyDsc -Force -AllowClobber
Install-Module -Name GPRegistryPolicyDsc -Force -AllowClobber
Install-Module -Name NetworkingDsc -Force -AllowClobber

# Install Guest Configuration module (for packaging)
Install-Module -Name GuestConfiguration -Force -AllowClobber

Write-Host "`nDONE. Environment is clean." -ForegroundColor Cyan
