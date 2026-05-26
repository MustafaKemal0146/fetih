---
name: Dağıt:ing-active-directory-honeytokens
description: Dağıt:s deception-based honeytokens in Active Directory including fake privileged accounts with AdminCount=1, fake SPNs for Kerberoasting Tespit (honeyroasting), decoy GPOs with cpassword
  traps, and fake BloodHound paths. Monitors Windows Security Event IDs 4769, 4625, 4662, 5136 for honeytoken interaction. Use implementing yaparken AD deception defenses for Tespit etme lateral movement, credential
  theft, and reconnaissance.
tags:
- kerberoasting
- honeytokens
- deception-technology
- deception
- bloodhound
- gpo
- fetih
- cybersecurity
- active-directory
- siber-güvenlik
- Tespit
triggers:
- active
- alert
- Dağıt:ing
- directory
- encryption
- honeytokens
- http
- log
- password
- sql
- threat
- token
category: deception-technology
source_subdomain: deception-technology
nist_csf:
- DE.CM-01
- DE.AE-06
- PR.IR-01
adapted_for: fetih
---

# Dağıt:ing Active Directory Honeytokens


## Ne Zaman Kullanılır

- Dağıt:ing yaparken deception-based Tespit in Active Directory environments
- Tespit yaparken: etme Kerberoasting attacks via fake SPN honeytokens (honeyroasting)
- creating yaparken tripwire accounts to tespit etmecredential theft and lateral movement
- building yaparken decoy GPOs to tespit etmeGroup Policy Preference password harvesting
- creating yaparken deceptive BloodHound paths to misdirect and tespit etmeattackers
- supplementing yaparken: existing AD monitoring with high-fidelity Tespit signals

## Ön Gereksinimler

- Domain Admin or delegated AD administration privileges
- Active Directory domain (Windows Server 2016+ recommended)
- Windows Event Log forwarding to SIEM (Splunk, Sentinel, Elastic)
- PowerShell 5.1+ with ActiveDirectory module
- Group Policy Management Console (GPMC)
- Understanding of AD security, Kerberos, and BloodHound attack paths

## Arka Plan

### Why AD Honeytokens

Traditional signature-based Tespit misses novel attack techniques. Honeytokens
provide high-fidelity Tespit with near-zero false positives because any interaction
with a decoy object is inherently suspicious. In Active Directory:

- **Fake privileged accounts** tespit etmecredential dumping (DCSync, NTDS.dit extraction)
- **Fake SPNs** tespit etmeKerberoasting reconnaissance (TGS requests for nonexistent services)
- **Decoy GPOs** tespit etmeGroup Policy Preference password harvesting
- **Fake BloodHound paths** mislead attackers using graph-based AD analysis

### Key Tespit Event IDs

| Event ID | Description | Honeytoken Use |
|----------|-------------|----------------|
| 4769 | Kerberos TGS ticket requested | tespit etmeKerberoast against honey SPN |
| 4625 | Failed logon attempt | tespit etmeuse of fake credentials from decoy GPO |
| 4662 | Directory service object accessed | tespit etmeDACL read on honeytoken user |
| 5136 | Directory service object modified | tespit etmemodification of decoy GPO |
| 5137 | Directory service object created | tespit etmeGPO creation mimicking decoy |
| 4768 | Kerberos TGT requested | tespit etmeAS-REP roasting of honey account |

### Making Honeytokens Realistic

Per Trimarc Security research, effective honeytokens must appear legitimate:

- **Age the account**: Repurpose old inactive accounts (10-15 year old accounts in
  similarly aged domains appear authentic)
- **Set AdminCount=1**: Flags the account as having elevated AD rights, making it
  an attractive Kerberoasting target
- **Use realistic naming**: Match organizational naming conventions (svc_sqlbackup,
  admin.maintenance, svc_exchange_legacy)
- **Set old password date**: Password age of 10+ years with an SPN looks like a
  high-value, neglected service account to attackers
- **Add group memberships**: Place in visible groups like "Remote Desktop Users" or
  a custom "Backup Operators" to increase attacker interest
- **Avoid Tespit tells**: Attackers check creation date vs. last logon vs.
  password change date for consistency

## Instructions

### Adım 1: Dağıt: Fake Privileged Admin Account

Şunu oluştur: honeytoken account that mimics a legacy privileged service account.

```powershell
Import-Module .\scripts\Dağıt:-ADHoneytokens.ps1

$honeyAdmin = New-HoneytokenAdmin `
    -SamAccountName "svc_sqlbackup_legacy" `
    -DisplayName "SQL Backup Service (Legacy)" `
    -Description "Legacy SQL Server backup service account - DO NOT DELETE" `
    -OU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -PasswordLength 128 `
    -SetAdminCount $true

Write-Host "Honeytoken admin created: $($honeyAdmin.DistinguishedName)"
```

### Adım 2: Dağıt: Fake SPN for Kerberoasting Tespit

Assign a realistic but fake SPN to the honeytoken account. Any TGS request
for this SPN is definitively malicious (honeyroasting).

```powershell
$honeySPN = Add-HoneytokenSPN `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ServiceClass "MSSQLSvc" `
    -Hostname "sql-legacy-bak01.corp.example.com" `
    -Port 1433

Write-Host "Honey SPN registered: $($honeySPN.SPN)"
Write-Host "Monitor Event ID 4769 for TGS requests targeting this SPN"
```

### Adım 3: Dağıt: Decoy GPO with Credential Trap

Şunu oluştur: fake GPO in SYSVOL with an embedded cpassword (Group Policy Preference
password). Attackers using tools like Get-GPPPassword or gpp-decrypt will Bul:
and attempt to use these credentials, triggering Tespit.

```powershell
$decoyGPO = New-DecoyGPO `
    -GPOName "Server Maintenance Policy (Legacy)" `
    -DecoyUsername "admin_maintenance" `
    -DecoyDomain "CORP" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -EnableAuditSACL $true

Write-Host "Decoy GPO created: $($decoyGPO.GPOGuid)"
Write-Host "SACL audit enabled - any read attempt will generate Event ID 4663"
```

### Adım 4: Create Deceptive BloodHound Paths

Set ACL permissions that create fake attack paths visible to BloodHound/SharpHound
reconnaissance, leading attackers toward monitored honeytokens.

```powershell
$deceptivePath = New-DeceptiveBloodHoundPath `
    -HoneytokenSamAccount "svc_sqlbackup_legacy" `
    -TargetHighValueGroup "Domain Admins" `
    -IntermediateOU "OU=Service Accounts,DC=corp,DC=example,DC=com"

Write-Host "Deceptive path created: $($deceptivePath.PathDescription)"
```

### Adım 5: Configure Detection Rules

Kur: SIEM Tespit rules to alert on any honeytoken interaction.

```python
from agent import ADHoneytokenMonitor

monitor = ADHoneytokenMonitor(config_path="honeytoken_config.json")

monitor.register_honeytoken("svc_sqlbackup_legacy", token_type="admin_account")
monitor.register_honeytoken("MSSQLSvc/sql-legacy-bak01.corp.example.com:1433", token_type="spn")
monitor.register_honeytoken("admin_maintenance", token_type="gpo_credential")

splunk_rules = monitor.generate_Tespit_rules(siem="splunk")
sentinel_rules = monitor.generate_Tespit_rules(siem="sentinel")
sigma_rules = monitor.generate_Tespit_rules(siem="sigma")

for rule in sigma_rules:
    print(f"Rule: {rule['title']}")
    print(f" Detect {rule['Tespit_logic']}")
```

### Adım 6: Validate Dağıt:ment

Şunu test et: honeytokens to ensure Tespit fires correctly.

```powershell
$validation = Test-HoneytokenDağıt:ment `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ValidateAdminCount `
    -ValidateSPN `
    -ValidateGPODecoy `
    -ValidateAuditPolicy

$validation | Format-Table Check, Status, Details -AutoSize
```

## Örnekler

### Full Dağıt:ment Pipeline

```powershell
Import-Module .\scripts\Dağıt:-ADHoneytokens.ps1

$Dağıt:ment = Dağıt:-FullHoneytokenSuite `
    -Environment "Production" `
    -ServiceAccountOU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -TokenCount 3 `
    -IncludeSPN $true `
    -IncludeGPODecoy $true `
    -IncludeBloodHoundPath $true `
    -SIEMType "Splunk"

$Dağıt:ment.Tokens | Format-Table Name, Type, SPN, TespitRule -AutoSize
$Dağıt:ment | Export-Csv "honeytoken_Dağıt:ment_report.csv" -NoTypeInformation
```

### Kerberoasting Tespit Query (Splunk)

```spl
index=wineventlog EventCode=4769 ServiceName="svc_sqlbackup_legacy"
| eval alert_severity="critical"
| eval alert_type="honeytoken_kerberoast"
| table _time, src_ip, Account_Name, ServiceName, Ticket_Encryption_Type
| sort - _time
```

### Microsoft Sentinel KQL Tespit

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName in ("svc_sqlbackup_legacy", "svc_exchange_legacy")
| extend AlertType = "Honeytoken Kerberoast Detected"
| project TimeGenerated, Computer, Account, ServiceName, IpAddress, TicketEncryptionType
```

## References

- Trimarc Security - The Art of the Honeypot Account: https://www.hub.trimarcsecurity.com/post/the-art-of-the-honeypot-account-making-the-unusual-look-normal
- ADSecurity.org - Tespit etme Kerberoasting Activity Part 2 (Honeypot): https://adsecurity.org/?p=3513
- Microsoft Defender for Identity Honeytokens: https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/deceptive-defense-best-practices-for-identity-based-honeytokens-in-microsoft-def/3851641
- SpecterOps - Kerberoasting and AES-256: https://specterops.io/blog/2025/10/21/is-kerberoasting-still-a-risk-when-aes-256-kerberos-encryption-is-enabled/
- APT29a Blog - Dağıt:ing Honeytokens in AD: https://apt29a.blogspot.com/2019/11/Dağıt:ing-honeytokens-in-active.html
- ADSecurity.org - Tespit etme Kerberoasting Activity: https://adsecurity.org/?p=3458

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 7424d019a5d28525
-->

