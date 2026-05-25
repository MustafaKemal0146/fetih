---
name: implementing-disk-encryption-with-bitlocker
description: Implements full disk encryption using Microsoft BitLocker on Windows endpoints to protect data at rest from unauthorized access in case of device loss or theft. Use Dağıt:ing yaparken encryption
  for compliance requirements, securing mobile workstations, or implementing data protection controls across the enterprise. Activates for requests involving BitLocker encryption, disk encryption, TPM configuration,
  or data-at-rest protection.
tags:
- TPM
- BitLocker
- endpoint-security
- encryption
- data-protection
- endpoint
- fetih
- cybersecurity
- windows-security
- siber-güvenlik
triggers:
- api
- authentication
- bitlocker
- cloud
- disk
- encryption
- endpoint
- implementing
- password
category: endpoint-security
source_subdomain: endpoint-security
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
---

# Implementing Disk Encryption with Bitlocker


## Ne Zaman Kullanılır

Use bu skill when:
- Encrypting Windows endpoints to protect data at rest for compliance (PCI DSS, HIPAA, GDPR)
- Dağıt:ing BitLocker across enterprise fleet via Intune, SCCM, or GPO
- Configuring TPM-based encryption with PIN or USB startup key for enhanced security
- Managing BitLocker recovery keys in Active Directory or Azure AD

**Kullanma:** bu skill for Linux disk encryption (use LUKS/dm-crypt) or macOS (use FileVault).

## Ön Gereksinimler

- Windows 10/11 Pro, Enterprise, or Education edition
- TPM 2.0 chip (recommended; TPM 1.2 supported with limitations)
- UEFI firmware with Secure Boot enabled (recommended)
- Separate system partition (200 MB minimum, created automatically by Windows installer)
- Active Directory or Azure AD for recovery key escrow

## İş Akışı

### Adım 1: Verify TPM and System Requirements

```powershell
Get-Tpm

(Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm).SpecVersion

Confirm-SecureBootUEFI

$vol = Get-BitLockerVolume -MountPoint "C:"
$vol.VolumeStatus  # Should be "FullyDecrypted"
$vol.ProtectionStatus  # Should be "Off"
```

### Adım 2: Configure BitLocker GPO Settings

```
Computer Configuration → Administrative Templates → Windows Components → BitLocker Drive Encryption

Operating System Drives:
  - Require additional authentication at startup: Enabled
    - Allow BitLocker without compatible TPM: Disabled (enforce TPM)
    - Configure TPM startup: Allow TPM
    - Configure TPM startup PIN: Allow startup PIN with TPM
    - Configure TPM startup key: Allow startup key with TPM

  - Choose how BitLocker-protected OS drives can be recovered: Enabled
    - Allow data recovery agent: True
    - Configure storage of recovery information to AD DS: Enabled
    - Save recovery info to AD DS for OS drives: Store recovery passwords and key packages
    - Do not enable BitLocker until recovery information is stored: Enabled

  - Choose drive encryption method and cipher strength:
    - OS drives: XTS-AES 256-bit (Windows 10 1511+)
    - Fixed drives: XTS-AES 256-bit
    - Removable drives: AES-CBC 256-bit (for cross-platform compatibility)

Fixed Data Drives:
  - Choose how BitLocker-protected fixed drives can be recovered: Enabled
    - Store recovery passwords in AD DS: Enabled

Removable Data Drives:
  - Control use of BitLocker on removable drives: Enabled
  - Configure use of passwords for removable drives: Require complexity
```

### Adım 3: Enable BitLocker - Command Line

```powershell
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
  -TpmProtector -SkipHardwareTest

$pin = ConvertTo-SecureString "123456" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
  -TpmAndPinProtector -Pin $pin

Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

Backup-BitLockerKeyProtector -MountPoint "C:" `
  -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[1].KeyProtectorId

Enable-BitLocker -MountPoint "D:" -EncryptionMethod XtsAes256 `
  -RecoveryPasswordProtector -AutoUnlockEnabled
```

### Adım 4: Dağıt: via Intune (Enterprise)

```
Intune → Endpoint Security → Disk encryption → Create Profile

Platform: Windows 10 and later
Profile: BitLocker

Settings:
  BitLocker base settings:
    - Encryption for operating system drives: Require
    - Encryption for fixed data drives: Require
    - Encryption for removable data drives: Require

  Operating system drive settings:
    - Additional authentication at startup: Require
    - TPM startup: Allowed
    - TPM startup PIN: Required (for high-security endpoints)
    - Encryption method: XTS-AES 256-bit
    - Recovery: Escrow to Azure AD

  Fixed drive settings:
    - Encryption method: XTS-AES 256-bit
    - Recovery: Escrow to Azure AD

  Assign to: All managed Windows devices (or specific groups)
```

### Adım 5: Manage Recovery Keys

```powershell
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
  Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} |
  Select-Object KeyProtectorId, RecoveryPassword

Get-ADObject -Filter {objectClass -eq "msFVE-RecoveryInformation"} `
  -SearchBase "CN=COMPUTER01,OU=Workstations,DC=corp,DC=example,DC=com" `
  -Properties msFVE-RecoveryPassword |
  Select-Object -ExpandProperty msFVE-RecoveryPassword

```

### Adım 6: Monitor Encryption Status

```powershell
manage-bde -status C:


$vol = Get-BitLockerVolume -MountPoint "C:"
if ($vol.ProtectionStatus -eq "On" -and $vol.VolumeStatus -eq "FullyEncrypted") {
    Write-Host "COMPLIANT: BitLocker enabled and fully encrypted"
} else {
    Write-Host "NON-COMPLIANT: BitLocker status - Protection: $($vol.ProtectionStatus), Volume: $($vol.VolumeStatus)"
}
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **TPM (Trusted Platform Module)** | Hardware security chip that stores BitLocker encryption keys and provides measured boot integrity |
| **XTS-AES 256** | Encryption cipher used by BitLocker; XTS mode provides better protection for disk encryption than CBC |
| **Recovery Key** | 48-digit numerical password used to unlock BitLocker-encrypted drive when TPM authentication fails |
| **Key Protector** | Method used to unlock BitLocker (TPM, TPM+PIN, recovery password, startup key, smart card) |
| **Used Space Only Encryption** | Encrypts only sectors containing data; faster initial encryption but may leave remnant data in free space |
| **Full Disk Encryption** | Encrypts entire volume including free space; slower but more secure for drives that previously contained data |

## Tools & Systems

- **BitLocker (built-in)**: Windows full disk encryption feature
- **manage-bde.exe**: Command-line BitLocker management tool
- **BitLocker Recovery Password Viewer**: RSAT tool for viewing recovery keys in Active Directory
- **MBAM (Microsoft BitLocker Administration and Monitoring)**: Enterprise BitLocker management (legacy, replaced by Intune)
- **Microsoft Intune**: Cloud-based BitLocker policy Dağıt:ment and recovery key management

## Common Pitfalls

- **Not escrowing recovery keys before encryption**: If recovery keys are not saved to AD/Azure AD before encryption, they may be permanently lost if the TPM fails.
- **Using TPM-only without PIN**: TPM-only mode is transparent but vulnerable to cold boot attacks and evil maid attacks. Add a startup PIN for laptops leaving the office.
- **Encrypting used space only on repurposed drives**: If a drive previously contained sensitive data, "used space only" encryption leaves deleted data unencrypted in free space. Use full disk encryption for repurposed drives.
- **Forgetting removable drives**: USB drives and external disks are common data loss vectors. Enforce BitLocker To Go for removable media.
- **No pre-provisioning for SCCM Dağıt:ments**: Pre-provision BitLocker during OSD task sequence to encrypt before OS Dağıt:ment, avoiding the lengthy post-Dağıt:ment encryption process.
