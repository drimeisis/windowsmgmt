<# 
    Server2025_Baseline.ps1
    v1.3 - Final Corrected Version
#>

Configuration Server2025_Baseline {

    param(
        [string[]] $NodeName = 'localhost'
    )

    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -ModuleName AuditPolicyDsc
    Import-DscResource -ModuleName GPRegistryPolicyDsc
    Import-DscResource -ModuleName NetworkingDsc

    Node $NodeName {

        ############################################################
        # 1. LOCAL SECURITY POLICY (MERGED BLOCK)
        ############################################################
        
        SecurityOption MainSecurityOptions {
            Name = 'SecurityOptions'

            # Accounts
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'

            # Interactive Logon
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'

            # Microsoft Network Client
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'

            # Network Access
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            
            # NOTE: 'Restrict_clients_allowed_to_make_remote_calls_to_SAM' is removed from here 
            # and handled via Registry below to prevent DSC Schema crashes.

            # Network Security
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Network_security_LDAP_client_signing_requirements = 'Negotiate signing'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'

            # Domain Member
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'

            # System Objects
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'

            # UAC Settings
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'

            # Audit Policy Override
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }

        ############################################################
        # 1.1 Restrict Remote SAM (Registry Method)
        ############################################################
        
        RegistryPolicyFile RestrictRemoteSam {
            Key        = 'SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName  = 'RestrictRemoteSAM'
            ValueType  = 'String'
            ValueData  = 'O:BAG:BAD:(A;;RC;;;BA)'
            TargetType = 'ComputerConfiguration'
        }

        ############################################################
        # 2. FIREWALL – DOMAIN, PRIVATE, PUBLIC
        ############################################################

        FirewallProfile FirewallDomainProfile {
            Name                  = 'Domain'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            LogBlocked            = 'True'
            LogAllowed            = 'True'
        }

        FirewallProfile FirewallPrivateProfile {
            Name                  = 'Private'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            LogBlocked            = 'True'
            LogAllowed            = 'True'
        }

        FirewallProfile FirewallPublicProfile {
            Name                  = 'Public'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            LogBlocked            = 'True'
            LogAllowed            = 'True'
        }

        ############################################################
        # 3. ADVANCED AUDIT POLICY CONFIGURATION
        ############################################################

        # Account Logon
        AuditPolicySubcategory Audit_CredentialValidation_S {
            Name      = 'Credential Validation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_CredentialValidation_F {
            Name      = 'Credential Validation'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Account Management
        AuditPolicySubcategory Audit_SecurityGroupManagement_S {
            Name      = 'Security Group Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_UserAccountManagement_S {
            Name      = 'User Account Management'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_UserAccountManagement_F {
            Name      = 'User Account Management'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Detailed Tracking
        AuditPolicySubcategory Audit_PnPActivity_S {
            Name      = 'Plug and Play Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_ProcessCreation_S {
            Name      = 'Process Creation'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # Logon / Logoff
        AuditPolicySubcategory Audit_AccountLockout_F {
            Name      = 'Account Lockout'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_GroupMembership_S {
            Name      = 'Group Membership'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_Logon_S {
            Name      = 'Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_Logon_F {
            Name      = 'Logon'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherLogonLogoff_S {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherLogonLogoff_F {
            Name      = 'Other Logon/Logoff Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SpecialLogon_S {
            Name      = 'Special Logon'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }

        # Object Access
        AuditPolicySubcategory Audit_DetailedFileShare_F {
            Name      = 'Detailed File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_FileShare_S {
            Name      = 'File Share'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_FileShare_F {
            Name      = 'File Share'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherObjectAccess_S {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherObjectAccess_F {
            Name      = 'Other Object Access Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_RemovableStorage_S {
            Name      = 'Removable Storage'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_RemovableStorage_F {
            Name      = 'Removable Storage'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Policy Change
        AuditPolicySubcategory Audit_AuditPolicyChange_S {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_AuditPolicyChange_F {
            Name      = 'Audit Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_AuthenticationPolicyChange_S {
            Name      = 'Authentication Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_AuthorizationPolicyChange_S {
            Name      = 'Authorization Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_MPSSVCRuleLevelPolicyChange_S {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_MPSSVCRuleLevelPolicyChange_F {
            Name      = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherPolicyChange_F {
            Name      = 'Other Policy Change Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # Privilege Use
        AuditPolicySubcategory Audit_SensitivePrivilegeUse_S {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SensitivePrivilegeUse_F {
            Name      = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        # System
        AuditPolicySubcategory Audit_OtherSystemEvents_S {
            Name      = 'Other System Events'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_OtherSystemEvents_F {
            Name      = 'Other System Events'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SecurityStateChange_S {
            Name      = 'Security State Change'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SecuritySystemExtension_S {
            Name      = 'Security System Extension'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SystemIntegrity_S {
            Name      = 'System Integrity'
            AuditFlag = 'Success'
            Ensure    = 'Present'
        }
        AuditPolicySubcategory Audit_SystemIntegrity_F {
            Name      = 'System Integrity'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }

        ############################################################
        # 4. EVENT LOG SIZE
        ############################################################

        # Application log size 32768 KB
        RegistryPolicyFile EventLog_ApplicationSize {
            Key        = 'SYSTEM\CurrentControlSet\Services\EventLog\Application'
            ValueName  = 'MaxSize'
            ValueType  = 'Dword'
            ValueData  = 32768
            TargetType = 'ComputerConfiguration'
        }

        # Security log size 196608 KB
        RegistryPolicyFile EventLog_SecuritySize {
            Key        = 'SYSTEM\CurrentControlSet\Services\EventLog\Security'
            ValueName  = 'MaxSize'
            ValueType  = 'Dword'
            ValueData  = 196608
            TargetType = 'ComputerConfiguration'
        }

        # System log size 32768 KB
        RegistryPolicyFile EventLog_SystemSize {
            Key        = 'SYSTEM\CurrentControlSet\Services\EventLog\System'
            ValueName  = 'MaxSize'
            ValueType  = 'Dword'
            ValueData  = 32768
            TargetType = 'ComputerConfiguration'
        }

        ############################################################
        # 5. ADMINISTRATIVE TEMPLATES / REGISTRY-BASED POLICIES
        ############################################################

        # Machine inactivity limit = 900 seconds
        RegistryPolicyFile MachineInactivityLimit {
            Key        = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'InactivityTimeoutSecs'
            ValueType  = 'Dword'
            ValueData  = 900
            TargetType = 'ComputerConfiguration'
        }

        # Microsoft network server: Digitally sign communications (always) = Enabled
        RegistryPolicyFile MicrosoftNetworkServerSign {
            Key        = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName  = 'RequireSecuritySignature'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Control Panel / Personalization – Prevent lock screen camera
        RegistryPolicyFile NoLockScreenCamera {
            Key        = 'Software\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenCamera'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Prevent lock screen slideshow
        RegistryPolicyFile NoLockScreenSlideshow {
            Key        = 'Software\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenSlideshow'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Apply UAC restrictions to local accounts on network logons
        RegistryPolicyFile LocalAccountTokenFilterPolicy {
            Key        = 'System\CurrentControlSet\Control\Lsa'
            ValueName  = 'LocalAccountTokenFilterPolicy'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

        # SMBv1 client / server disabled
        RegistryPolicyFile DisableSmb1Server {
            Key        = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName  = 'SMB1'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile DisableSmb1Client {
            Key        = 'SYSTEM\CurrentControlSet\Services\mrxsmb10'
            ValueName  = 'Start'
            ValueType  = 'Dword'
            ValueData  = 4 # Disabled
            TargetType = 'ComputerConfiguration'
        }

        # NetBT NodeType = P-node
        RegistryPolicyFile NetBT_NodeType_P {
            Key        = 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName  = 'NodeType'
            ValueType  = 'Dword'
            ValueData  = 2
            TargetType = 'ComputerConfiguration'
        }

        # MSS: Disable IP source routing IPv4/IPv6
        RegistryPolicyFile DisableIPv4SourceRouting {
            Key        = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName  = 'DisableIPSourceRouting'
            ValueType  = 'Dword'
            ValueData  = 2
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile DisableIPv6SourceRouting {
            Key        = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueName  = 'DisableIPSourceRouting'
            ValueType  = 'Dword'
            ValueData  = 2
            TargetType = 'ComputerConfiguration'
        }

        # MSS: Allow ICMP redirects to override OSPF generated routes = Disabled
        RegistryPolicyFile DisableIcmpRedirects {
            Key        = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueName  = 'EnableICMPRedirect'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

        # MSS: NoNameReleaseOnDemand
        RegistryPolicyFile NoNameReleaseOnDemand {
            Key        = 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
            ValueName  = 'NoNameReleaseOnDemand'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Turn off multicast name resolution
        RegistryPolicyFile DisableLLMNR {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName  = 'EnableMulticast'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

        # Windows Defender Firewall: Allow logging + Prohibit notifications
        RegistryPolicyFile Wdfw_ProhibitNotifications {
            Key        = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'
            ValueName  = 'DisableNotifications'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Hardened UNC Paths (SYSVOL & NETLOGON)
        RegistryPolicyFile HardenedUNC_SYSVOL {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName  = '\\*\SYSVOL'
            ValueType  = 'String'
            ValueData  = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile HardenedUNC_NETLOGON {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueName  = '\\*\NETLOGON'
            ValueType  = 'String'
            ValueData  = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            TargetType = 'ComputerConfiguration'
        }

        # System / Audit Process Creation – include command line
        RegistryPolicyFile IncludeCommandLineInProcessCreation {
            Key        = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Credentials Delegation – Encryption Oracle Remediation = Force Updated Clients
        RegistryPolicyFile EncryptionOracleRemediation {
            Key        = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
            ValueName  = 'AllowEncryptionOracle'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

        # Early Launch Antimalware – Good, unknown and bad but critical
        RegistryPolicyFile Elam_BootStartPolicy {
            Key        = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName  = 'DriverLoadPolicy'
            ValueType  = 'Dword'
            ValueData  = 3
            TargetType = 'ComputerConfiguration'
        }

        # LSA protection (Run as PPL, with UEFI lock)
        RegistryPolicyFile Lsa_RunAsPPL {
            Key        = 'SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName  = 'RunAsPPL'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Logon: Enumerate local users on domain-joined computers = Disabled
        RegistryPolicyFile DontEnumerateLocalUsers {
            Key        = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'DontEnumerateLocalUsers'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # RPC: Restrict unauthenticated RPC clients
        RegistryPolicyFile RpcRestrictRemoteClients {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName  = 'RestrictRemoteClients'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # AutoPlay policies – Turn off AutoPlay on all drives
        RegistryPolicyFile TurnOffAutoPlay {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName  = 'NoDriveTypeAutoRun'
            ValueType  = 'Dword'
            ValueData  = 255
            TargetType = 'ComputerConfiguration'
        }

        # Disallow Autoplay for non-volume devices
        RegistryPolicyFile DisallowAutoplayNonVolume {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueName  = 'NoAutoplayfornonVolume'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Windows Defender SmartScreen – Explorer: Warn and prevent bypass
        RegistryPolicyFile SmartScreen_Explorer_Enable {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'EnableSmartScreen'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile SmartScreen_Explorer_Block {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'ShellSmartScreenLevel'
            ValueType  = 'String'
            ValueData  = 'Block'
            TargetType = 'ComputerConfiguration'
        }

        # Windows Search – Allow indexing of encrypted files = Disabled
        RegistryPolicyFile Search_IndexEncryptedFiles {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueName  = 'AllowIndexingEncryptedStoresOrItems'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

        # Windows PowerShell – Script Block Logging
        RegistryPolicyFile PS_ScriptBlockLogging_Enable {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueName  = 'EnableScriptBlockLogging'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # WinRM Client / Service – disable Basic, Digest, unencrypted, etc.
        RegistryPolicyFile WinRMClient_AllowBasic {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName  = 'AllowBasic'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile WinRMClient_AllowUnencrypted {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName  = 'AllowUnencryptedTraffic'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile WinRMClient_DisallowDigest {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueName  = 'AllowDigest'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile WinRMService_AllowBasic {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName  = 'AllowBasic'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile WinRMService_AllowUnencrypted {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName  = 'AllowUnencryptedTraffic'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile WinRMService_DisallowRunAs {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueName  = 'DisableRunAs'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Remote Desktop Services – drive redirection, security, etc.
        RegistryPolicyFile Rds_DisableDriveRedirection {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fDisableCdm'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile Rds_AlwaysPromptForPassword {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fPromptForPassword'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile Rds_RequireSecureRPC {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fEncryptRPCTraffic'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile Rds_EncryptionLevel_High {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'MinEncryptionLevel'
            ValueType  = 'Dword'
            ValueData  = 3
            TargetType = 'ComputerConfiguration'
        }

        # RSS Feeds – prevent enclosures
        RegistryPolicyFile Rss_PreventEnclosures {
            Key        = 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueName  = 'DisableEnclosureDownload'
            ValueType  = 'Dword'
            ValueData  = 1
            TargetType = 'ComputerConfiguration'
        }

        # Windows Installer – disable user control and elevated installs
        RegistryPolicyFile Installer_AllowUserControl {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName  = 'EnableUserControl'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }
        RegistryPolicyFile Installer_AlwaysInstallElevated {
            Key        = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueName  = 'AlwaysInstallElevated'
            ValueType  = 'Dword'
            ValueData  = 0
            TargetType = 'ComputerConfiguration'
        }

    } # end Node
} # end Configuration
