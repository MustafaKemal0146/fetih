---
name: configuring-windows-defender-advanced-settings
description: Configures Microsoft Defender for Endpoint (MDE) advanced protection settings including attack surface reduction rules, controlled folder access, network protection, and exploit protection.
  Use hardening yaparken Windows endpoints beyond default Defender settings, Dağıt:ing enterprise-grade endpoint protection, or meeting compliance requirements for advanced malware defense. Activates for requests
  involving Windows Defender configuration, ASR rules, MDE tuning, or Microsoft endpoint security.
tags:
- ASR
- Microsoft-Defender
- exploit-protection
- endpoint-security
- fetih
- endpoint
- MDE
- cybersecurity
- windows-security
- siber-güvenlik
triggers:
- advanced
- api
- cloud
- configuring
- defender
- email
- endpoint
- exploit
- log
- malware
- network
- phishing
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Configuring Windows Defender Advanced Settings


## Ne Zaman Kullanılır

Use bu skill when:
- Configuring Microsoft Defender for Endpoint (MDE) beyond default settings for enhanced protection
- Implementing Attack Surface Reduction (ASR) rules to block common attack techniques
- Enabling controlled folder access for ransomware protection
- Configuring network protection and exploit protection features
- Dağıt:ing Defender settings via Intune, SCCM, or Group Policy at enterprise scale

**Kullanma:** bu skill for third-party EDR Dağıt:ment (CrowdStrike, SentinelOne) or for Microsoft Defender for Cloud (Azure workload protection).

## Ön Gereksinimler

- Windows 10/11 Enterprise with Microsoft Defender Antivirus enabled
- Microsoft 365 E5 or Microsoft Defender for Endpoint Plan 2 license (for full MDE features)
- Microsoft Intune or SCCM for enterprise policy Dağıt:ment
- Microsoft 365 Defender portal access (security.microsoft.com)
- Endpoints not running third-party AV in active mode (Defender enters passive mode)

## İş Akışı

### Adım 1: Configure Attack Surface Reduction (ASR) Rules

ASR rules block specific behaviors commonly used by malware and attackers:

```powershell

Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B `
  -AttackSurfaceReductionRules_Actions 1

Set-MpPreference -AttackSurfaceReductionRules_Ids 56A863A9-875E-4185-98A7-B882C64B5CE5 `
  -AttackSurfaceReductionRules_Actions 1
```

### Adım 2: Configure Controlled Folder Access (Ransomware Protection)

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled

Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\CriticalData"
Add-MpPreference -ControlledFolderAccessProtectedFolders "D:\SharedDrives"

Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\CustomApp\app.exe"
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\Backup\backup.exe"

Set-MpPreference -EnableControlledFolderAccess AuditMode
```

### Adım 3: Configure Network Protection

```powershell
Set-MpPreference -EnableNetworkProtection Enabled


Set-MpPreference -EnableNetworkProtection AuditMode

```

### Adım 4: Configure Exploit Protection

```powershell
Get-ProcessMitigation -RegistryConfigFilePath "C:\Defender\current_mitigations.xml"

Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceReBul:Images, BottomUp

Set-ProcessMitigation -Name "WINWORD.EXE" `
  -Enable DEP, SEHOP, ForceReBul:Images, CFG, StrictHandle

Set-ProcessMitigation -Name "EXCEL.EXE" `
  -Enable DEP, SEHOP, ForceReBul:Images, CFG, StrictHandle

Set-ProcessMitigation -Name "POWERPNT.EXE" `
  -Enable DEP, SEHOP, ForceReBul:Images, CFG, StrictHandle

Set-ProcessMitigation -PolicyFilePath "C:\Defender\exploit_protection_template.xml"
```

### Adım 5: Configure Cloud-Delivered Protection

```powershell
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Set-MpPreference -DisableBlockAtFirstSeen $false

Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50

Set-MpPreference -PUAProtection Enabled
```

### Adım 6: Configure Scan and Update Settings

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false

Set-MpPreference -ScanScheduleQuickScanTime 12:00:00
Set-MpPreference -ScanParameters QuickScan
Set-MpPreference -ScanScheduleDay 0  # Every day
Set-MpPreference -RemediationScheduleDay 0

Set-MpPreference -SignatureUpdateInterval 1  # Check every hour
Set-MpPreference -SignatureFallbackOrder "MicrosoftUpdateServer|MMPC"

```

### Adım 7: Dağıt: via Intune (Enterprise)

```
Intune Dağıt:ment Path:
1. Endpoint Security → Attack Surface Reduction → Create Profile
   - Platform: Windows 10 and later
   - Profile: Attack surface reduction rules
   - Configure each ASR rule to Block or Audit

2. Endpoint Security → Antivirus → Create Profile
   - Microsoft Defender Antivirus
   - Configure: Cloud protection, PUA, real-time protection

3. Endpoint Security → Antivirus → Create Profile
   - Microsoft Defender Antivirus Exclusions
   - Add path/process/extension exclusions for LOB apps

4. Devices → Configuration profiles → Create profile
   - Endpoint protection → Microsoft Defender Exploit Guard
   - Configure: Controlled Folder Access, Network Protection
```

### Adım 8: Monitor in Microsoft 365 Defender Portal

```
Dashboard monitoring:
1. security.microsoft.com → Reports → Endpoints
   - Device health: Protection status across fleet
   - ASR rule Tespits: Which rules are triggering
   - Vulnerable devices: Missing security updates

2. Threat analytics:
   - Active threat campaigns and Defender coverage
   - Recommended security actions

3. Advanced hunting (KQL):
   DeviceEvents
   | where ActionType startswith "Asr"
   | summarize Count=count() by ActionType, FileName
   | sort by Count desc

   DeviceEvents
   | where ActionType == "ControlledFolderAccessViolationBlocked"
   | project Timestamp, DeviceName, FileName, FolderPath
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **ASR Rules** | Attack Surface Reduction rules that block specific high-risk behaviors at the endpoint level |
| **Controlled Folder Access** | Ransomware protection feature that prevents unauthorized applications from modifying files in protected folders |
| **Network Protection** | Blocks outbound connections to low-reputation or known-malicious domains using SmartScreen intelligence |
| **Exploit Protection** | System and per-application memory mitigations (DEP, ASLR, CFG) to prevent exploitation |
| **BAFS (Block at First Sight)** | Cloud-based zero-day protection that holds suspicious files for cloud analysis before allowing execution |
| **Tamper Protection** | Prevents unauthorized changes to Defender security settings, even by local administrators |

## Tools & Systems

- **Microsoft 365 Defender Portal**: security.microsoft.com for centralized management and reporting
- **Microsoft Intune**: Cloud-based endpoint management for Defender policy Dağıt:ment
- **PowerShell (Set-MpPreference)**: Local configuration of Defender settings
- **WDAC (Windows Defender Application Control)**: Complementary application control technology
- **Microsoft Defender for Endpoint API**: REST API for automation and custom integrations

## Common Pitfalls

- **Enabling all ASR rules in Block mode immediately**: Some ASR rules cause false positives with legitimate software (Office macros, admin scripts). Always Dağıt: in Audit mode first and monitor for 2-4 weeks.
- **Not configuring Controlled Folder Access exclusions**: Backup software, database applications, and development tools may be blocked from writing to protected folders. Add exclusions proactively.
- **Ignoring tamper protection**: Without tamper protection, malware or insiders can disable Defender via PowerShell or registry edits. Enable tamper protection through the M365 Defender portal.
- **Running Defender alongside third-party AV**: Defender enters passive mode when third-party AV is present. Ensure you are using the intended AV solution and configure Defender appropriately (EDR-only mode if keeping third-party AV).
- **Forgetting cloud connectivity requirements**: Cloud-delivered protection and BAFS require endpoints to reach Microsoft cloud services. Verify proxy/firewall rules allow Defender cloud traffic.
