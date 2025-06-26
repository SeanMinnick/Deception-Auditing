<#

File: deployment1.ps1
Author : Sean Minnick (@SeanMinnick)
Description: A PowerShell script to automatically deploy a suite of AD deceptive objects.
Required Dependencies: ActiveDirectory Module by Microsoft

#>

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Deploy-Deception2.psm1" -Force
Write-Host "`n[+] Deploying Active Directory Honeypots..."

try {
    # --- Create a Decoy OU ---
    $decoyOUName = "AutoDecoys"
    $domainDN = (Get-ADDomain).DistinguishedName
    $decoyOUDN = "OU=$decoyOUName,$domainDN"

    Write-Host "`n[+] Creating OU: $decoyOUName"
    New-DecoyOU -OUName $decoyOUName | Out-Null

    Write-Host "[+] Deploying OU auditing..."
    Deploy-OUDeception -OUDistinguishedName $decoyOUDN -AuditFlag Success -Verbose

    # --- Create Decoy Users ---
    Write-Host "`n[+] Creating and deploying decoy users..."
    for ($i = 1; $i -le 3; $i++) {
        $first = "decoy"
        $last = "user$i"
        $pass = "P@ssw0rd$i"

        New-DecoyUser -UserFirstName $first -UserLastName $last -Password $pass -OUDistinguishedName $decoyOUDN |
            Deploy-UserDeception -UserFlag PasswordNeverExpires -PasswordInDescription "legacyAdmin123!" -Verbose
    }

    # --- Create Decoy Computers ---
    Write-Host "`n[+] Creating and deploying decoy computers..."
    for ($i = 1; $i -le 3; $i++) {
        $compName = "DECOY-COMP0$i"

        New-DecoyComputer -ComputerName $compName -OUDistinguishedName $decoyOUDN |
            Deploy-ComputerDeception -OperatingSystem "Windows Server 2003" -PropertyFlag TrustedForDelegation -Verbose
    }

    # --- Create and Deploy Decoy GPO ---
    $gpoName = "PrivilegedAccessBackup"
    Write-Host "`n[+] Creating and deploying decoy GPO: $gpoName"

    New-DecoyGPO -Name $gpoName `
                 -Comment "Legacy admin script GPO - audit before deletion" `
                 -TargetOU $decoyOUDN `
                 -AddFakeScripts `
                 -MakeReadable `
                 -Verbose | Out-Null

    Deploy-GPODeception -GpoName $gpoName -Right ReadProperty -AuditFlag Success -Verbose

    Write-Host "`n[✔] Honeypot deployment completed successfully." -ForegroundColor Green
}
catch {
    Write-Error "[-] Error during honeypot deployment: $_"
}
