---
name: Tespit etme-misconfigured-azure-storage
description: Tespit etme misconfigured Azure Storage accounts including publicly accessible blob containers, missing encryption settings, overly permissive SAS tokens, disabled logging, and network access
  violations using Azure CLI, PowerShell, and Microsoft Defender for Storage.
tags:
- azure
- blob-storage
- fetih
- data-protection
- cloud-security
- cybersecurity
- storage-security
- siber-güvenlik
- sas-tokens
triggers:
- AWS
- Azure
- GCP
- alert
- api
- authentication
- azure
- bulut güvenliği
- cloud
- cloud security
- container
- Tespit etme
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detection Misconfigured Azure Storage


## Ne Zaman Kullanılır

- performing yaparken a security audit of Azure Storage accounts across subscriptions
- responding yaparken to Microsoft Defender for Storage alerts about anonymous access or data exfiltration
- compliance yaparken: requires verification of encryption, network restrictions, and access logging
- investigating yaparken potential data exposure through publicly accessible blob containers
- onboarding yaparken Azure subscriptions and establishing storage security baselines

**Kullanma:** for Azure SQL or Cosmos DB security auditing (use dedicated database security tools), for real-time threat Tespit on storage operations (use Defender for Storage), or for Azure Files or Data Lake Gen2 specific auditing without adapting the checks.

## Ön Gereksinimler

- Azure CLI installed and authenticated (`az login`) with Reader and Storage Account Contributor roles
- Az PowerShell module installed for advanced queries (`Install-Module Az.Storage`)
- Microsoft Defender for Storage enabled for threat Tespit
- Erişim: Azure Resource Graph for cross-subscription queries
- ScoutSuite or Prowler Azure provider for automated assessment

## İş Akışı

### Adım 1: Enumerate All Storage Accounts and Basic Configuration

List all storage accounts across subscriptions and assess their baseline security settings.

```bash
az storage account list \
  --query "[].{Name:name, ResourceGroup:resourceGroup, Location:location, Kind:kind, Sku:sku.name, HttpsOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion, PublicAccess:allowBlobPublicAccess}" \
  -o table

az graph query -q "
  Resources
  | where type == 'microsoft.storage/storageaccounts'
  | project name, resourceGroup, subscriptionId, location,
    properties.allowBlobPublicAccess,
    properties.enableHttpsTrafficOnly,
    properties.minimumTlsVersion,
    properties.networkAcls.defaultAction
" -o table
```

### Adım 2: tespit etmePublicly Accessible Blob Containers

Identify storage accounts and containers allowing anonymous public Erişim: blob data.

```bash
for account in $(az storage account list --query "[].name" -o tsv); do
  public=$(az storage account show --name "$account" --query "allowBlobPublicAccess" -o tsv)
  echo "$account: allowBlobPublicAccess=$public"
done

for account in $(az storage account list --query "[?allowBlobPublicAccess==true].name" -o tsv); do
  key=$(az storage account keys list --account-name "$account" --query "[0].value" -o tsv)
  echo "=== $account ==="
  az storage container list \
    --account-name "$account" \
    --account-key "$key" \
    --query "[?properties.publicAccess!='off' && properties.publicAccess!=null].{Container:name, PublicAccess:properties.publicAccess}" \
    -o table 2>/dev/null
done

curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list" | head -50
```

### Adım 3: Audit Network Access and Firewall Rules

Check for storage accounts accessible from all networks versus those restricted to specific VNets or IP ranges.

```bash
az storage account list \
  --query "[?networkRuleSet.defaultAction=='Allow'].{Name:name, DefaultAction:networkRuleSet.defaultAction, VNetRules:networkRuleSet.virtualNetworkRules}" \
  -o table

for account in $(az storage account list --query "[].name" -o tsv); do
  echo "=== $account ==="
  az storage account show --name "$account" \
    --query "{DefaultAction:networkRuleSet.defaultAction, IPRules:networkRuleSet.ipRules[*].ipAddressOrRange, VNetRules:networkRuleSet.virtualNetworkRules[*].virtualNetworkResourceId, Bypass:networkRuleSet.bypass}" \
    -o json
done

az network private-endpoint list \
  --query "[?privateLinkServiceConnections[0].groupIds[0]=='blob'].{Name:name, Storage:privateLinkServiceConnections[0].privateLinkServiceId}" \
  -o table
```

### Adım 4: Verify Encryption Settings and Key Management

Ensure all storage accounts use encryption at rest with appropriate key management (Microsoft-managed or customer-managed keys).

```bash
for account in $(az storage account list --query "[].name" -o tsv); do
  echo "=== $account ==="
  az storage account show --name "$account" \
    --query "{Encryption:encryption.services, KeySource:encryption.keySource, KeyVaultUri:encryption.keyVaultProperties.keyVaultUri, InfraEncryption:encryption.requireInfrastructureEncryption}" \
    -o json
done

az storage account list \
  --query "[?encryption.requireInfrastructureEncryption!=true].{Name:name, KeySource:encryption.keySource}" \
  -o table

az storage account list \
  --query "[?minimumTlsVersion!='TLS1_2'].{Name:name, TLS:minimumTlsVersion}" \
  -o table
```

### Adım 5: Audit Shared Access Signatures and Access Keys

Identify overly permissive SAS tokens and check for access key usage patterns.

```bash
for account in $(az storage account list --query "[].name" -o tsv); do
  echo "=== $account ==="
  az storage account keys list \
    --account-name "$account" \
    --query "[].{KeyName:keyName, CreationTime:creationTime}" \
    -o table
done

az storage account list \
  --query "[].{Name:name, AllowSharedKeyAccess:allowSharedKeyAccess}" \
  -o table

for account in $(az storage account list --query "[].name" -o tsv); do
  key=$(az storage account keys list --account-name "$account" --query "[0].value" -o tsv 2>/dev/null)
  for container in $(az storage container list --account-name "$account" --account-key "$key" --query "[].name" -o tsv 2>/dev/null); do
    policies=$(az storage container policy list --container-name "$container" --account-name "$account" --account-key "$key" 2>/dev/null)
    [ -n "$policies" ] && echo "$account/$container: $policies"
  done
done
```

### Adım 6: Check Diagnostic Logging and Monitoring

Şunu doğrula: storage analytics logging and Azure Monitor diagnostic settings are enabled.

```bash
for account in $(az storage account list --query "[].name" -o tsv); do
  rg=$(az storage account show --name "$account" --query "resourceGroup" -o tsv)
  echo "=== $account ==="
  az monitor diagnostic-settings list \
    --resource "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$account" \
    --query "[].{Name:name, Logs:logs[*].category, Metrics:metrics[*].category}" \
    -o json 2>/dev/null || echo "  No diagnostic settings configured"
done

for account in $(az storage account list --query "[].name" -o tsv); do
  key=$(az storage account keys list --account-name "$account" --query "[0].value" -o tsv 2>/dev/null)
  az storage logging show \
    --account-name "$account" \
    --account-key "$key" \
    --services b 2>/dev/null
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| Blob Public Access | Storage account setting that allows anonymous read Erişim: blob containers and their contents without authentication |
| Shared Access Signature | Time-limited URI with embedded authentication tokens granting delegated Erişim: Azure Storage resources with specific permissions |
| Network ACL Default Action | Storage firewall setting that Belirle:s whether traffic is allowed or denied by default, with exceptions for specified IPs and VNets |
| Customer-Managed Key | Encryption key stored in Azure Key Vault that the customer controls for storage encryption instead of Microsoft-managed keys |
| Stored Access Policy | Named policy on a container that defines SAS permissions, start/expiry times, and can be revoked independently of individual SAS tokens |
| Defender for Storage | Microsoft Defender plan providing threat Tespit for anomalous storage access patterns, malware uploads, and data exfiltration |

## Tools & Systems

- **Azure CLI**: Primary tool for querying storage account configuration, containers, and access policies
- **Azure Resource Graph**: Cross-subscription query engine for efficient enumeration of storage security settings at scale
- **Microsoft Defender for Storage**: Threat Tespit service identifying anomalous access patterns and potential data exfiltration
- **Prowler Azure**: Open-source tool with automated storage security checks aligned to CIS Azure Foundations
- **ScoutSuite**: Multi-cloud auditing tool with Azure storage-specific checks for public access, encryption, and networking

## Common Scenarios

### Scenario: Tespit etme a Storage Account Exposed by a Developer Misconfiguration

**Context**: A developer creates a storage account for a web application and enables blob public Erişim: serve static files. They accidentally store API keys and database connection strings in a publicly accessible container.

**Approach**:
1. Run `az storage account list` filtering for `allowBlobPublicAccess=true`
2. Enumerate containers with public access level set to `blob` or `container`
3. List contents of public containers to identify sensitive files
4. Check Defender for Storage alerts for anomalous access from unexpected IPs
5. Immediately set `allowBlobPublicAccess` to `false` on the storage account
6. Rotate any exposed credentials found in public containers
7. Enable network ACLs restricting Erişim: the application VNet
8. Configure Azure CDN or Front Door for legitimate public content delivery

**Pitfalls**: Disabling blob public access immediately breaks applications serving content publicly. Coordinate with the development team and implement Azure CDN before disabling public access. SAS tokens generated before a key rotation remain valid until expiry unless the underlying storage key is regenerated.

## Output Format

```
Azure Storage Security Audit Report
======================================
Subscription: Production (SUB-ID)
Assessment Date: 2026-02-23
Storage Accounts Audited: 24

CRITICAL Bul:INGS:
[STOR-001] Public Blob Access Enabled
  Account: webapp-static-prod
  Container: uploads (PublicAccess: blob)
  Risk: Anonymous users can read all blobs in the container
  Contents: 1,247 files including .env and config.json
  Remediation: Disable allowBlobPublicAccess, use Azure CDN with SAS

[STOR-002] Storage Account Open to All Networks
  Account: data-lake-analytics
  Default Action: Allow (no network restrictions)
  Risk: Accessible from any network including the internet
  Remediation: Set default action to Deny, add VNet rules

SUMMARY:
  Public blob access enabled:           3 / 24
  Open to all networks:                 8 / 24
  Missing infrastructure encryption:   12 / 24
  TLS version below 1.2:                2 / 24
  No diagnostic logging:               10 / 24
  Shared key access enabled:           18 / 24
  Keys not rotated in 90+ days:        14 / 24
```
