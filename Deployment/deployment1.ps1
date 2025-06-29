$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy -ErrorAction Stop
Write-Host " Deploying Active Directory Honeypots..."

try {
    # --- Ask user for Decoy OU Name ---
    $decoyOUName = Read-Host "Enter name for the decoy OU (e.g., AutoDecoys)"
    $domainDN = (Get-ADDomain).DistinguishedName
    $decoyOUDN = "OU=$decoyOUName,$domainDN"

    Write-Host " Creating OU: $decoyOUName"
    New-DecoyOU -OUName $decoyOUName | Out-Null

    Write-Host " Deploying OU auditing..."
    Deploy-OUDeception -OUDistinguishedName $decoyOUDN -AuditFlag Success -Verbose

    # --- Prompt for Decoy Users ---
    $userCount = Read-Host "How many decoy users do you want to create?"
    for ($i = 1; $i -le [int]$userCount; $i++) {
        $first = Read-Host "Enter first name for user $i"
        $last = Read-Host "Enter last name for user $i"
        $pass = Read-Host "Enter password for $first $last"

        New-DecoyUser -UserFirstName $first -UserLastName $last -Password $pass -OUDistinguishedName $decoyOUDN |
            Deploy-UserDeception -UserFlag PasswordNeverExpires -PasswordInDescription "legacyAdmin123!" -Verbose
    }

    # --- Prompt for Decoy Computers ---
    $compCount = Read-Host "How many decoy computers do you want to create?"
    for ($i = 1; $i -le [int]$compCount; $i++) {
        $compName = Read-Host "Enter name for computer $i (e.g., DECOY-COMP01)"

        New-DecoyComputer -ComputerName $compName -OUDistinguishedName $decoyOUDN |
            Deploy-ComputerDeception -OperatingSystem "Windows Server 2003" -PropertyFlag TrustedForDelegation -Verbose
    }

    # --- Prompt for GPO Name ---
    $gpoName = Read-Host "Enter name for the decoy GPO"
    Write-Host " Creating and deploying decoy GPO: $gpoName"

    New-DecoyGPO -Name $gpoName `
                 -Comment "Legacy admin script GPO - audit before deletion" `
                 -TargetOU $decoyOUDN `
                 -AddFakeScripts `
                 -MakeReadable `
                 -Verbose | Out-Null

    Deploy-GPODeception -GpoName $gpoName -Right ReadProperty -AuditFlag Success -Verbose

    Write-Host " Honeypot deployment completed successfully."
} catch {
    Write-Error " Error during honeypot deployment: $($_)"
} finally {
    Write-Host 'Deployment Success'
}
