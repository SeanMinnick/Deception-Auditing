# Deception-Auditing

This is a repository combining Deploy-Deception by Nikhil "SamratAshok" Mittal and Set-AuditRule by Roberto "Cyb3rWard0g" Rodriguez
The goal is to create an updated toolset to deploy deceptive AD objects and audit them to detect activity.

Added Functionality :

Merged Set-AuditRule into the deploy deception function set. Allows you to import everything with one script and set audit rules on existing objects within the Deploy-Deception functionality. The internal function operates for the native Deploy-Deception functions but also works to set audit rules on files and registry items. 

New-DecoyOU - Allows you to create a new OU with any name that can be piped into Deploy-OUDeception to setup audit rules

New-DecoyGPO - Allows you to create a new GPO, you can set any comment on the GPO, link it to any OU, link intriguing scripts to make the GPO more appealing to attackers, and set the GPO to be readable to all authenticated users so that automatic enumeration will trigger audit rules. This is also piped into a similar Deploy-GPODeception function to enable auditing. 

Save-HoneyAudit - Allows you save a distinguished name of an AD object to a file in the same directory as the script, it will keep track of your honeypots and allow you to pull the audit events into your terminal at any time using Pull-HoneyAudit. Honeypot tracking file stores the GUID's of the objects added in a plaintext format. Encryption will be added. 

Pull-HoneyAudit - Automatically pulls recent audit events from the honeypots saved with Save-HoneyAudit.

# Usage

## Set-AuditRule
The merged Set-AuditRule function allows users to create auditing rules on Registry Keys, Files, and Active Directory Objects.

### Registry Examples:
Set-AuditRule -RegistryPath 'HKLM:\Software\MyKey' -WellKnownSidType WorldSid -Rights ReadKey -InheritanceFlags None -PropagationFlags None -AuditFlags Success

Set-AuditRule -RegistryPath "HKLM:\SOFTWARE\TestAuditKey" -WellKnownSidType WorldSid -Rights Delete -InheritanceFlags None -PropagationFlags None -AuditFlags Success -RemoveAuditing $true

Set-AuditRule -RegistryPath "HKLM:\SOFTWARE\TestAuditKey" -WellKnownSidType LocalSystemSid -Rights EnumerateSubKeys -InheritanceFlags None -PropagationFlags None -AuditFlags Success

### Registry Parameters:
-RegistryPath --> Path to the registry key you want to audit

-WellKnownSidType --> Specifies who the audit rule applies to, takes any SID type (AccountGuestSid, LocalSystemSid, etc...)

-Rights --> Specifies which action to audit, accepts any RegistryRights value (ReadKey, WriteKey, CreateSubKey, etc...)

-InheritanceFlags --> Controls whether the audit rule applies to subkeys of the target key (None, ContainerInherit)

-PropogationFlags --> Works together with inheritance flags to control how the rule applies to child objects (None, NoPropogateInherit, InheritOnly)

-AuditFlags --> Determines which events to audit: successful access, failed access, or both. (Success, Failure, None)

-RemoveAuditing --> Optional Parameter which defaults to false, set to true to remove auditing rule on the specified object

### File Examples:
Set-AuditRule -FilePath "C:\TestFolder\testfile.txt" -WellKnownSidType WorldSid -Rights ReadData -InheritanceFlags None -PropagationFlags None -AuditFlags Success

Set-AuditRule -FilePath "C:\TestFolder" -WellKnownSidType AccountDomainUsersSid -Rights WriteData -InheritanceFlags ContainerInherit,ObjectInherit -PropagationFlags InheritOnly -AuditFlags Failure

### File Parameters:
-FilePath --> Any valid file or folder path

All other parameters are identical to registry keys

### Active Directory Examples:
Set-AuditRule -AdObjectPath "LDAP://CN=TestUser,CN=Users,DC=domain,DC=com" -WellKnownSidType AccountDomainUsersSid -Rights ReadProperty -InheritanceFlags ThisObjectOnly -AuditFlags Success

Set-AuditRule -AdObjectPath "LDAP://OU=TestOU,DC=domain,DC=com" -WellKnownSidType WorldSid -Rights ListChildren -InheritanceFlags ThisObjectOnly -AuditFlags Success -AttributeGUID "bf967aba-0de6-11d0-a285-00aa003049e2"

### Active Directory Parameters:
-AdObjectPath --> Any valid AD object path

Same parameters as other examples

-AttributeGUID --> Optional parameter that allows you to audit a specific attribute within an object

## New-DecoyUser
Allows you to create new Users in AD, can be piped into Deploy-UserDeception to create an audited user

### Examples:
New-DecoyUser -UserFirstName John -UserLastName Doe -Password P@ssw0rd

New-DecoyUser -UserFirstName Admin -UserLastName Backup -Password StrongPass123 -OUDistinguishedName "OU=Decoys,DC=domain,DC=com"

### Parameters:
-UserFirstName --> Specifies first name of the decoy user

-UserLastName --> Specifies last name of the decoy user

-Password --> Sets a password for the decoy user

-OUDistinguishedName --> Optional parameter to put user in a specific OU, defaults to Users OU

## New-DecoyComputer
Allows you to create new Computer objects in AD. Can be piped into Deploy-ComputerDeception to create an audited decoy computer.

### Examples:
New-DecoyComputer -ComputerName Workstation01

New-DecoyComputer -ComputerName FakeServer -OUDistinguishedName "OU=DecoyComputers,DC=domain,DC=com"

### Parameters:
-ComputerName --> Specifies the name of the decoy computer

-OUDistinguishedName --> Optional parameter to place the computer in a specific OU, defaults to Computers OU

## New-DecoyGroup
Allows you to create new Groups in AD.

### Examples:
New-DecoyGroup -GroupName "Privileged Users"

New-DecoyGroup -GroupName "Shadow Admins" -GroupScope Universal

### Parameters:
-GroupName --> Specifies the name of the decoy group

-GroupScope --> Optional parameter to set the group scope, defaults to Global  
Valid options: DomainLocal, Global, Universal

## New-DecoyOU
Creates a decoy Organizational Unit in Active Directory. Useful for segmenting decoy objects or organizing fake assets.

### Examples:
New-DecoyOU -OUName "DecoyServers"

New-DecoyOU -OUName "FakeUsers" -ParentDistinguishedName "OU=Departments,DC=domain,DC=com"

### Parameters:
-OUName --> Specifies the name of the OU to be created

-ParentDistinguishedName --> Optional parameter for where to create the OU, defaults to domain root

## New-DecoyGPO
Creates a decoy Group Policy Object (GPO) that can be linked to an OU and enhanced with fake scripts and visibility bait.

### Examples:
New-DecoyGPO -Name "PrivilegedAccessBackup"

New-DecoyGPO -Name "Legacy-Security-Policy" -Comment "Legacy config - under review" -TargetOU "OU=Decoys,DC=domain,DC=com"

New-DecoyGPO -Name "FakeLogonPolicy" -TargetOU "OU=FakeOU,DC=domain,DC=com" -AddFakeScripts -MakeReadable

### Parameters:
-Name --> Name of the decoy GPO to create

-Comment --> Optional description visible in GPMC

-TargetOU --> Optional Distinguished Name of the OU to link the GPO to

-AddFakeScripts --> Adds fake logon scripts to SYSVOL (optional switch)

-MakeReadable --> Grants GPO read access to Authenticated Users for increased discoverability (optional switch)

# Deploy Auditing

## Deploy-UserDeception
Deploys a decoy user and configures auditing to log Security Event 4662 when specific rights or properties are accessed.

### Examples:
Deploy-UserDeception -DecoySamAccountName "honeypot1" -UserFlag PasswordNeverExpires

Deploy-UserDeception -DecoySamAccountName "honeypot2" -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a

Deploy-UserDeception -DecoySamAccountName "trap1" -UserFlag AllowReversiblePasswordEncryption -Right ReadControl

### Parameters:
-DecoySamAccountName --> SamAccountName of the decoy user (can also use -DecoyDistinguishedName)

-DecoyDistinguishedName --> DistinguishedName of the decoy user (alternative to -DecoySamAccountName)

-UserFlag --> Optional flag to add attacker-attractive attributes to the user  
Options: DoesNotRequirePreAuth, AllowReversiblePasswordEncryption, PasswordNeverExpires, TrustedForDelegation, TrustedToAuthForDelegation

-PasswordInDescription --> Optional string to leave a fake password in the user's Description field

-SPN --> Set an interesting SPN (e.g., MSSQLSvc/host.domain.com)

-Principal --> The principal (user or group) for whom auditing is enabled (default: Everyone)

-Right --> Right to audit when used against the user (default: ReadProperty)  
Options: GenericAll, GenericRead, GenericWrite, ReadControl, ReadProperty, WriteDacl, WriteOwner, WriteProperty

-GUID --> Optional property GUID to scope auditing to a specific AD attribute

-AuditFlag --> Success or Failure logging (default: Success)

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Deploy-PrivilegedUserDeception
Creates or configures a decoy user with high-value privileges (e.g., Domain Admin or DCSync rights) while enforcing protections like denied logon, and configures auditing to log 4662 or 4768 events.

### Examples:
Deploy-PrivilegedUserDeception -DecoySamAccountName "decda" -Technique DomainAdminsMembership -Protection DenyLogon

Deploy-PrivilegedUserDeception -DecoySamAccountName "decda" -Technique DCSyncRights -Protection DenyLogon

Deploy-PrivilegedUserDeception -DecoySamAccountName "decda" -Technique DomainAdminsMembership -Protection DenyLogon -CreateLogon

### Parameters:
-DecoySamAccountName --> SamAccountName of the decoy user (or use -DecoyDistinguishedName)

-DecoyDistinguishedName --> DistinguishedName of the decoy user (alternative to -DecoySamAccountName)

-Technique --> Privileged technique to apply  
Options: DomainAdminsMembership, DCSyncRights

-Protection --> Optional protections against abuse  
Options: DenyLogon

-Principal --> The principal for which auditing is configured (default: Everyone)

-Right --> Right to audit (default: ReadControl)

-GUID --> Optional property GUID for targeted auditing

-AuditFlag --> Success or Failure logging (default: Success)

-CreateLogon --> Creates a fake logon event for the decoy user on the DC to simulate activity (helps with logon count artifacts)

-logonCount --> Number of fake logons to simulate (default: 1)

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Deploy-ComputerDeception  
Deploys or configures a decoy computer object in Active Directory and enables auditing to log Security Event 4662.

### Examples:
Deploy-ComputerDeception -ComputerName "decoy-web" -PropertyFlag TrustedForDelegation -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a

Deploy-ComputerDeception -ComputerName "decoy-backup" -OperatingSystem "Windows Server 2003" -Right ReadControl

Deploy-ComputerDeception -ComputerName "decoy-db" -SPN "MSSQLSvc/db.internal" -AuditFlag Failure

### Parameters:
-ComputerName --> SamAccountName of the decoy computer

-OperatingSystem --> Optional OS value to assign (e.g., "Windows Server 2003")

-SPN --> Optional SPN to make the computer appear interesting (e.g., MSSQLSvc/host)

-PropertyFlag --> Optional flag to enable attacker-attractive traits  
Options: AllowReversiblePasswordEncryption, PasswordNeverExpires, TrustedForDelegation

-Principal --> The user or group to audit (default: Everyone)

-Right --> Right to audit (default: ReadProperty)  
Options: GenericAll, GenericRead, GenericWrite, ReadControl, ReadProperty, WriteDacl, WriteOwner, WriteProperty

-GUID --> Optional GUID of the property to scope the audit

-AuditFlag --> Success or Failure logging (default: Success)

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Deploy-GroupDeception  
Deploys or configures a decoy Active Directory group and enables auditing to log Security Event 4662.

### Examples:
Deploy-GroupDeception -DecoyGroupName "Forest Admins" -AddMembers "testuser1" -AddToGroup "dnsadmins" -Right ReadControl

Deploy-GroupDeception -DecoyGroupName "OpsSecurity" -GUID bc0ac240-79a9-11d0-9020-00c04fc2d4cf

Deploy-GroupDeception -DecoyGroupName "PrivGroup1" -Right ReadProperty -AuditFlag Failure

### Parameters:
-DecoyGroupName --> SamAccountName of the decoy group

-AddMembers --> Optional list of users to add as members of the group

-AddToGroup --> Optional group to which the decoy group will be added

-Principal --> The user or group to audit (default: Everyone)

-Right --> Right to audit (default: ReadProperty)  
Options: GenericAll, GenericRead, GenericWrite, ReadControl, ReadProperty, WriteDacl, WriteOwner, WriteProperty

-GUID --> Optional property GUID to scope auditing to a specific AD attribute

-AuditFlag --> Success or Failure logging (default: Success)

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Deploy-OUDeception  
Applies auditing to a target Organizational Unit (OU) to log Security Event 4662 when accessed by specific well-known SID types.

### Examples:
Deploy-OUDeception -OUDistinguishedName "OU=DecoyOU,DC=corp,DC=local" -Right ReadProperty

Deploy-OUDeception -OUDistinguishedName "OU=SensitiveOU,DC=lab,DC=local" -WellKnownSidType AuthenticatedUserSid -Right WriteDacl -AuditFlag Failure

Deploy-OUDeception -OUDistinguishedName "OU=HR,DC=domain,DC=com" -AttributeGUID 91e647de-d96f-4b70-9557-d63ff4f3ccd8

### Parameters:
-OUDistinguishedName --> Distinguished name of the OU to apply auditing to

-WellKnownSidType --> SID principal to audit  
Options: WorldSid, AuthenticatedUserSid, AccountDomainUsersSid, AccountDomainAdminsSid, EveryoneSid  
(Default: WorldSid)

-Right --> Right to audit (default: ReadProperty)  
Options: GenericAll, GenericRead, GenericWrite, ReadControl, ReadProperty, WriteDacl, WriteOwner, WriteProperty

-AuditFlag --> Success or Failure logging (default: Success)

-InheritanceFlags --> Scope of inheritance for audit rule  
Options: None, All, Descendents, SelfAndChildren (default: None)

-AttributeGUID --> Optional GUID of the attribute to scope the audit

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Deploy-GPODeception  
Applies auditing to a Group Policy Object (GPO) in Active Directory to log Security Event 4662 when accessed or modified.

### Examples:
Deploy-GPODeception -GpoName "Default Domain Policy" -Right ReadControl

Deploy-GPODeception -GpoName "Decoy GPO" -AuditFlag Failure

Deploy-GPODeception -GpoName "LateralTrapPolicy" -Principal "Authenticated Users" -RemoveAuditing $true

### Parameters:
-GpoName --> Name of the target GPO (must match exactly)

-Principal --> User or group to audit (default: Everyone)

-Right --> Right to audit (default: ReadProperty)  
Options: GenericAll, GenericRead, GenericWrite, ReadControl, ReadProperty, WriteDacl, WriteOwner, WriteProperty

-AuditFlag --> Success or Failure logging (default: Success)

-RemoveAuditing --> Optional switch to remove previously set auditing rules

## Save-HoneyAudit
Saves an AD object into a records file to be tracked for later use.

### Examples:
Save-HoneyAudit -DN "OU=AuditTesting,DC=doazlab,DC=com"

Save-HoneyAudit -DN "CN=fakeuser1,OU=Honeypots,DC=doazlab,DC=com"

### Parameters:
-DN --> Distinguished name of the target object to be saved for later use.

## Pull-HoneyAudit
Pulls recent audit events from Event Viewer for all objects stored via Save-HoneyAudit. Displays audit events for each object in terminal.

### Examples:
Pull-HoneyAudit

No parameters are used, it will automatically use the same directory tracking file and run on all objects listed in the file.