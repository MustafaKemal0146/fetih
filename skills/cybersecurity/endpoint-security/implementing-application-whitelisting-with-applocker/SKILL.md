---
name: implementing-application-whitelisting-with-applocker
description: Implements application whitelisting using Windows AppLocker to restrict unauthorized software execution on endpoints, reducing attack surface from malware, unauthorized tools, and shadow IT.
  Use enforcing yaparken application control policies, meeting compliance requirements for software restriction, or preventing execution of unsigned or untrusted binaries. Activates for requests involving AppLocker,
  application whitelisting, software restriction, or executable control.
tags:
- application-whitelisting
- software-restriction
- endpoint-security
- fetih
- endpoint
- cybersecurity
- windows-security
- siber-güvenlik
- AppLocker
triggers:
- application
- applocker
- endpoint
- hash
- implementing
- log
- password
- whitelisting
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Implementing Application Whitelisting with Applocker


## Ne Zaman Kullanılır

Use bu skill when:
- Implementing application control to prevent unauthorized software execution on Windows endpoints
- Meeting compliance requirements (PCI DSS 6.4.3, NIST 800-53 CM-7, ACSC Essential Eight)
- Blocking common attack vectors: living-off-the-land binaries (LOLBins), script-based attacks, unauthorized admin tools
- Restricting software installation in kiosk, POS, or high-security environments

**Kullanma:** bu skill for macOS/Linux application control (use OS-native tools like Gatekeeper or AppArmor) or for enterprise-grade WDAC (Windows Defender Application Control) Dağıt:ments.

## Ön Gereksinimler

- Windows 10/11 Enterprise or Education, or Windows Server 2016+
- Application Identity service (AppIDSvc) enabled on target endpoints
- Active Directory with Group Policy Management Console (GPMC)
- Complete application inventory of approved software
- Test OU with representative endpoints for policy validation

## İş Akışı

### Adım 1: Inventory Approved Applications

Before creating AppLocker rules, catalog all legitimate software:

```powershell
Get-AppLockerFileInformation -Directory "C:\Program Files" -Recurse `
  -FileType Exe | Export-Csv "C:\AppLocker\app_inventory_progfiles.csv" -NoTypeInformation

Get-AppLockerFileInformation -Directory "C:\Program Files (x86)" -Recurse `
  -FileType Exe | Export-Csv "C:\AppLocker\app_inventory_progfiles86.csv" -NoTypeInformation

Get-AppLockerFileInformation -Directory "C:\Windows" -Recurse `
  -FileType Exe | Export-Csv "C:\AppLocker\app_inventory_windows.csv" -NoTypeInformation
```

### Adım 2: Şunu oluştur:ppLocker Policy with Default Rules

```powershell


$defaultRules = Get-AppLockerPolicy -Local -Xml
Set-AppLockerPolicy -XmlPolicy $defaultRules -Merge
```

### Adım 3: Create Publisher-Based Rules (Preferred)

Publisher rules are the most maintainable since they survive application updates:

```xml
<!-- Example AppLocker policy XML for publisher rules -->
<RuleCollection Type="Exe" EnforcementMode="AuditOnly">
  <!-- Default: Allow Windows binaries -->
  <FilePublisherRule Id="a9e18c21-ff54-4677-b3ac-4b9a03261f6c"
    Name="Allow Microsoft signed" Description="Allow all Microsoft-signed executables"
    UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
      <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION*"
        ProductName="*" BinaryName="*">
        <BinaryVersionRange LowSection="*" HighSection="*"/>
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>

  <!-- Allow specific third-party vendor -->
  <FilePublisherRule Id="b2e28c32-aa65-5788-c4bd-5c0b14372e7d"
    Name="Allow Adobe Acrobat" Description="Allow Adobe-signed Acrobat executables"
    UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
      <FilePublisherCondition PublisherName="O=ADOBE INC.*"
        ProductName="ADOBE ACROBAT*" BinaryName="*">
        <BinaryVersionRange LowSection="*" HighSection="*"/>
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
</RuleCollection>
```

### Adım 4: Block Known-Abused Binaries (LOLBins)

```powershell

$denyPaths = @(
    "%SYSTEM32%\mshta.exe",
    "%SYSTEM32%\wscript.exe",
    "%SYSTEM32%\cscript.exe",
    "%SYSTEM32%\regsvr32.exe",
    "%SYSTEM32%\certutil.exe",
    "%SYSTEM32%\msbuild.exe",
    "%SYSTEM32%\installutil.exe",
    "%WINDIR%\Microsoft.NET\Framework\*\msbuild.exe",
    "%WINDIR%\Microsoft.NET\Framework64\*\msbuild.exe"
)

```

### Adım 5: Configure Script Rules

```
Script Rules (critical for preventing script-based attacks):

Allow:
  - Scripts in C:\Program Files\* (publisher or path-based)
  - Scripts in C:\Windows\* (default Windows scripts)
  - Approved admin scripts from \\fileserver\scripts\*

Deny (for standard users):
  - PowerShell scripts from user-writable directories
  - VBScript from %TEMP%, %APPDATA%, %USERPROFILE%\Downloads
  - JavaScript (.js) from any user-writable location

DLL Rules (optional, high performance impact):
  - Enable only in high-security environments
  - Allow signed DLLs from Program Files and Windows directories
  - Performance impact: 5-10% CPU increase during DLL loading
```

### Adım 6: Dağıt: in Audit Mode First

```powershell


Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

New-GPLink -Name "AppLocker-Audit-Policy" `
  -Target "OU=AppLocker-Pilot,DC=corp,DC=example,DC=com"

```

### Adım 7: Analyze Audit Logs and Refine Rules

```powershell
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" `
  -FilterXPath "*[System[EventID=8003]]" |
  Select-Object TimeCreated,
    @{N='User';E={$_.Properties[0].Value}},
    @{N='FilePath';E={$_.Properties[1].Value}},
    @{N='FileHash';E={$_.Properties[4].Value}} |
  Export-Csv "C:\AppLocker\audit_blocked_exes.csv" -NoTypeInformation

```

### Adım 8: Switch to Enforce Mode

```powershell


```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Application Whitelisting** | Security model that allows only pre-approved applications to execute, denying everything else by default |
| **Publisher Rule** | AppLocker rule based on digital signature; most resilient to application updates |
| **Path Rule** | AppLocker rule based on file system path; less secure as attackers can place files in allowed paths |
| **Hash Rule** | AppLocker rule based on file hash; most restrictive but breaks on every application update |
| **LOLBin** | Living Off the Land Binary; legitimate OS tool abused by attackers to avoid Tespit |
| **Audit Mode** | AppLocker logs policy violations without blocking; essential for rule refinement |
| **Enforcement Mode** | AppLocker actively blocks applications that violate policy rules |

## Tools & Systems

- **AppLocker (built-in)**: Windows application control feature in Enterprise/Education editions
- **WDAC (Windows Defender Application Control)**: More advanced successor to AppLocker for modern Windows
- **Microsoft LAPS**: Manages local admin passwords to prevent bypassing AppLocker via admin rights
- **WDAC Wizard**: GUI tool for creating Windows Defender Application Control policies
- **AaronLocker**: Open-source AppLocker rule generator by Microsoft employee (GitHub)

## Common Pitfalls

- **Skipping Audit mode**: Dağıt:ing AppLocker in Enforce mode without audit period will block critical applications and cause outages.
- **Relying solely on path rules**: Users with write Erişim: allowed paths (C:\Windows\Temp) can bypass path-based rules. Prefer publisher rules.
- **Not blocking user-writable directories**: The most common gap is allowing execution from %TEMP%, Downloads, or %APPDATA%.
- **Forgetting Application Identity service**: AppLocker requires the AppIDSvc service running. If it stops, all rules stop enforcing.
- **Admin bypass**: Local administrators can bypass AppLocker by default. For full enforcement, combine with WDAC which enforces for all users including admins.
- **DLL rule performance**: Enabling DLL rules creates significant performance overhead. Only enable in high-security environments where the tradeoff is justified.
