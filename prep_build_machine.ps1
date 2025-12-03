# 1. Install the Guest Configuration module
Install-Module -Name GuestConfiguration -Force

# 2. Ensure you have the DSC modules installed locally (so they can be packaged)
Install-Module -Name SecurityPolicyDsc -Force
Install-Module -Name AuditPolicyDsc -Force
Install-Module -Name GPRegistryPolicyDsc -Force
Install-Module -Name NetworkingDsc -Force

# 3. Install the Azure PowerShell module if you haven't
Install-Module -Name Az -Force
