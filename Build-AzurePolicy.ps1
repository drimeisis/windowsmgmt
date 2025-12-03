# Build-AzurePolicy.ps1

param(
    [string]$ResourceGroupName = "Arc-Management-RG",
    [string]$StorageAccountName = "arcdscstorage001",
    [string]$StorageContainerName = "dsc-configs",
    [string]$ConfigFilePath = ".\Server2025_Baseline.ps1",
    [string]$PolicyName = "Audit-Server2025-Baseline"
)

# 1. Connect to Azure
Connect-AzAccount

# 2. Compile the MOF (Locally)
Write-Host "Compiling MOF..."
. $ConfigFilePath
$MofPath = "C:\DSC\Build\MOF"
New-Item $MofPath -ItemType Directory -Force | Out-Null
Server2025_Baseline -NodeName 'localhost' -OutputPath $MofPath

# 3. Create the Guest Configuration Package (.zip)
# This bundles the MOF + All required Modules (SecurityPolicyDsc, etc.) into one zip.
Write-Host "Packaging Configuration..."
$PackagePath = "C:\DSC\Build\Package"
New-Item $PackagePath -ItemType Directory -Force | Out-Null

$Package = New-GuestConfigurationPackage `
    -Name "Server2025_Baseline" `
    -Configuration $MofPath `
    -Path $PackagePath `
    -Force

# 4. Upload to Azure Blob Storage
Write-Host "Uploading to Azure Storage..."
$Context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
New-AzStorageContainer -Name $StorageContainerName -Context $Context -Permission Blob -ErrorAction SilentlyContinue

$Blob = Set-AzStorageBlobContent `
    -File $Package.Path `
    -Container $StorageContainerName `
    -Blob "Server2025_Baseline.zip" `
    -Context $Context `
    -Force

# 5. Generate a SAS Token (valid for 3 years) so Arc agents can read it
$StartTime = Get-Date
$EndTime = $StartTime.AddYears(3)
$SasToken = New-AzStorageBlobSASToken `
    -Container $StorageContainerName `
    -Blob "Server2025_Baseline.zip" `
    -Permission r `
    -Context $Context `
    -StartTime $StartTime `
    -ExpiryTime $EndTime `
    -FullUri

# 6. Create the Azure Policy Definition
Write-Host "Creating Azure Policy Definition..."
$PolicyDefPath = "C:\DSC\Build\Policy"
New-Item $PolicyDefPath -ItemType Directory -Force | Out-Null

# We use 'ApplyAndAutoCorrect' to ensure enforcement
New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline via Guest Configuration" `
    -Path $PolicyDefPath `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -Verbose

# 7. Publish the Policy to Azure
$PolicyJson = Get-ChildItem "$PolicyDefPath\*.json" | Select-Object -First 1
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "Build Complete! Policy '$PolicyName' is now available in the Azure Portal."
