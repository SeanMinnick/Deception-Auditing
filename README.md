## Deception-Auditing

This is a repository combining Deploy-Deception by Nikhil "SamratAshok" Mittal and Set-AuditRule by Roberto "Cyb3rWard0g" Rodriguez
The goal is to create an updated toolset to deploy deceptive AD objects and audit them to detect activity.

Added Functionality :

Merged Set-AuditRule into the deploy deception function set. Allows you to import everything with one script and set audit rules on existing objects within the Deploy-Deception functionality. The internal function operates for the native Deploy-Deception functions but also works to set audit rules on files and registry items. 

New-DecoyOU - Allows you to create a new OU with any name that can be piped into Deploy-OUDeception to setup audit rules

New-DecoyGPO - Allows you to create a new GPO, you can set any comment on the GPO, link it to any OU, link intriguing scripts to make the GPO more appealing to attackers, and set the GPO to be readable to all authenticated users so that automatic enumeration will trigger audit rules. This is also piped into a similar Deploy-GPODeception function to enable auditing. 

## Usage

Set-AuditRule :
    The merged Set-AuditRule function allows users to create auditing rules on Registry Keys, Files, and Active Directory Objects.

    Registry Example: 
    Set-AuditRule -RegistryPath 'HKLM:\Software\MyKey' -WellKnownSidType WorldSid -Rights ReadKey -InheritanceFlags None -PropagationFlags None -AuditFlags Success

    -RegistryPath --> Path to the registry key you want to audit
    -WellKnownSidType --> Specifies who the audit rule applies to, takes any SID type (AccountGuestSid, LocalSystemSid, etc...)
    -Rights --> Specifies which action to audit, accepts any RegistryRights value (ReadKey, WriteKey, CreateSubKey, etc...)
    -InheritanceFlags --> Controls whether the audit rule applies to subkeys of the target key (None, ContainerInherit)
    -PropogationFlags --> Works together with inheritance flags to control how the rule applies to child objects (None, NoPropogateInherit, InheritOnly)
    -AuditFlags --> Determines which events to audit: successful access, failed access, or both. (Success, Failure, None)
    -RemoveAuditing --> Optional Parameter which defaults to false, set to true to remove auditing rule on the specified object