---
name: implementing-azure-defender-for-cloud
description: Implementing Microsoft Defender for Cloud to enable cloud security posture management, workload protection across VMs, containers, databases, and storage, configure security recommendations,
  and Kur: adaptive security controls with automated remediation.
tags:
- cwpp
- cspm
- siber-güvenlik
- azure
- fetih
- cloud-security
- cybersecurity
- defender-for-cloud
- security-recommendations
triggers:
- AWS
- Azure
- GCP
- alert
- azure
- bulut güvenliği
- cloud
- cloud security
- container
- defender
- email
- implementing
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
adapted_for: fetih
---

# Implementing Azure Defender for Cloud


## Ne Zaman Kullanılır

- enabling yaparken comprehensive security monitoring across Azure subscriptions
- implementing yaparken cloud workload protection for VMs, containers, SQL, storage, and Key Vault
- compliance yaparken: requirements demand continuous assessment against regulatory frameworks
- building yaparken adaptive security controls that respond to Detected threats
- centralizing yaparken: security Bul:ings from Azure-native and hybrid workloads

**Kullanma:** for non-Azure workload protection exclusively (use AWS Security Hub or GCP SCC), for application-level security testing (use Azure DevOps DAST/SAST), or for identity-specific protection (use Microsoft Defender for Identity).

## Ön Gereksinimler

- Azure subscription with Contributor or Security Admin role
- Azure Policy enabled for compliance assessment
- Log Analytics workspace for diagnostic data collection
- Azure Arc connected machines for hybrid server protection
- Pricing tier set to Standard for Defender plans (free tier provides CSPM only)

## İş Akışı

### Adım 1: Enable Defender for Cloud Plans

Enable the appropriate Defender plans for each workload type requiring protection.

```bash
az security pricing create --name CloudPosture --tier standard

az security pricing create --name VirtualMachines --tier standard \
  --subplan P2

az security pricing create --name Containers --tier standard

az security pricing create --name StorageAccounts --tier standard \
  --subplan PerStorageAccount

az security pricing create --name SqlServers --tier standard

az security pricing create --name KeyVaults --tier standard

az security pricing create --name AppServices --tier standard

az security pricing list \
  --query "[].{Plan:name, Tier:pricingTier, SubPlan:subPlan}" -o table
```

### Adım 2: Configure Auto-Provisioning of Security Agents

Enable automatic Dağıt:ment of monitoring agents to VMs and containers.

```bash
az security auto-provisioning-setting update \
  --name default --auto-provision on

az security workspace-setting create \
  --name default \
  --target-workspace "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/SecurityWorkspace"

az security setting update \
  --name Sentinel \
  --setting-kind DataExportSettings

az security auto-provisioning-setting list -o table
```

### Adım 3: Review and Prioritize Security Recommendations

Retrieve security recommendations and prioritize remediation based on secure score impact.

```bash
az security secure-score list \
  --query "[].{Name:displayName, Current:current, Max:max, Percentage:percentage}" -o table

az security assessment list \
  --query "[?status.code=='Unhealthy'].{Name:displayName, Severity:metadata.severity, Category:metadata.category, ResourceCount:status.cause}" \
  -o table

az security assessment list \
  --query "[?status.code=='Unhealthy'] | sort_by(@, &metadata.severity)" \
  -o table

az security assessment show \
  --name ASSESSMENT_ID \
  --query "{Name:displayName, Description:metadata.description, Severity:metadata.severity, Remediation:metadata.remediationDescription}"

az security secure-score-controls list \
  --query "[].{Control:displayName, CurrentScore:current, MaxScore:max, NotHealthy:notHealthyResourceCount}" \
  -o table
```

### Adım 4: Configure Regulatory Compliance Dashboard

Enable compliance standards and monitor adherence across subscriptions.

```bash
az security regulatory-compliance-standards list \
  --query "[].{Standard:name, State:state}" -o table

az security regulatory-compliance-standards update \
  --name "CIS-Azure-2.0" --state "Enabled"

az security regulatory-compliance-standards update \
  --name "PCI-DSS-4.0" --state "Enabled"

az security regulatory-compliance-standards update \
  --name "NIST-SP-800-53-R5" --state "Enabled"

az security regulatory-compliance-controls list \
  --standard-name "CIS-Azure-2.0" \
  --query "[].{Control:id, Description:displayName, State:state, PassedResources:passedResources, FailedResources:failedResources}" \
  -o table

az security regulatory-compliance-assessments list \
  --standard-name "CIS-Azure-2.0" \
  --control-name "2.1" \
  --query "[?state=='Failed'].{Assessment:id, State:state}" -o table
```

### Adım 5: Kur: Security Alerts and Automation

Configure alert notifications and automated response workflows.

```bash
az security contact create \
  --name "SecurityTeam" \
  --email "security-ops@company.com" \
  --phone "+1-555-0199" \
  --alert-notifications on \
  --alerts-to-admins on

az security alert list \
  --query "[?status=='Active'].{Name:alertDisplayName, Severity:severity, Time:timeGeneratedUtc, Status:status}" \
  -o table

az security automation create \
  --name "high-severity-alert-response" \
  --resource-group "security-rg" \
  --scopes "[{\"description\":\"Full subscription\",\"scopePath\":\"/subscriptions/SUB_ID\"}]" \
  --sources "[{
    \"eventSource\":\"Alerts\",
    \"ruleSets\":[{
      \"rules\":[{
        \"propertyJPath\":\"Severity\",
        \"propertyType\":\"String\",
        \"expectedValue\":\"High\",
        \"operator\":\"Equals\"
      }]
    }]
  }]" \
  --actions "[{
    \"logicAppResourceId\":\"/subscriptions/SUB_ID/resourceGroups/security-rg/providers/Microsoft.Logic/workflows/alert-response\",
    \"actionType\":\"LogicApp\"
  }]"
```

### Adım 6: Implement Adaptive Application Controls and JIT VM Access

Configure advanced workload protection features for runtime security.

```bash
az security jit-policy create \
  --resource-group "production-rg" \
  --name "jit-policy" \
  --virtual-machines "[{
    \"id\":\"/subscriptions/SUB_ID/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-01\",
    \"ports\":[
      {\"number\":22,\"protocol\":\"TCP\",\"allowedSourceAddressPrefix\":\"*\",\"maxRequestAccessDuration\":\"PT3H\"},
      {\"number\":3389,\"protocol\":\"TCP\",\"allowedSourceAddressPrefix\":\"*\",\"maxRequestAccessDuration\":\"PT3H\"}
    ]
  }]"

az security jit-policy initiate \
  --resource-group "production-rg" \
  --name "jit-policy" \
  --virtual-machines "[{
    \"id\":\"VM_ID\",
    \"ports\":[{\"number\":22,\"endTimeUtc\":\"2026-02-23T15:00:00Z\",\"allowedSourceAddressPrefix\":\"10.0.1.50\"}]
  }]"

az security adaptive-application-controls list \
  --query "[].{Group:displayName, Recommendation:recommendationAction, VMCount:vmRecommendations|length(@)}" \
  -o table
```

## Key Concepts

| Term | Definition |
|------|------------|
| Microsoft Defender for Cloud | Azure-native security platform providing CSPM and cloud workload protection (CWP) across Azure, hybrid, and multi-cloud environments |
| Secure Score | Numerical measure of an organization's security posture based on the percentage of security recommendations that have been implemented |
| Security Recommendation | Actionable guidance from Defender for Cloud to improve security posture, prioritized by severity and secure score impact |
| Defender Plan | Workload-specific protection tier (Servers, Containers, SQL, Storage, etc.) that enables advanced threat Tespit for specific resource types |
| Just-In-Time VM Access | Feature that reduces attack surface by blocking management ports (SSH/RDP) by default and granting time-limited access on request |
| Adaptive Application Controls | Machine-learning-based allowlisting that recommends which applications should be allowed to run on VMs |

## Tools & Systems

- **Microsoft Defender for Cloud**: Central security platform with CSPM, CWP, and regulatory compliance capabilities
- **Azure Policy**: Governance service used by Defender for Cloud to evaluate and enforce security configurations
- **Log Analytics Workspace**: Backend data store for security telemetry collected by Defender agents
- **Azure Logic Apps**: Workflow automation for incident response triggered by Defender alerts
- **Azure Arc**: Extends Defender for Cloud protection to hybrid and multi-cloud servers and Kubernetes clusters

## Common Scenarios

### Scenario: Rolling Out Defender for Cloud Across a Multi-Subscription Enterprise

**Context**: An enterprise with 20 Azure subscriptions needs to enable Defender for Cloud with server, container, and SQL protection while establishing a compliance baseline against CIS Azure 2.0.

**Approach**:
1. Enable the CSPM plan (CloudPosture) across all subscriptions using Azure Policy initiative
2. Enable Defender for Servers P2, Containers, and SQL on production subscriptions
3. Configure auto-provisioning to Dağıt: Log Analytics agents to all VMs
4. Enable CIS Azure 2.0 and PCI DSS 4.0 compliance standards
5. Create security contacts and configure alert notifications to the SOC team
6. Kur: workflow automation for High severity alerts via Logic Apps
7. Enable JIT VM access for all production servers to eliminate persistent SSH/RDP exposure
8. Şunu oluştur: weekly Secure Score report for executive stakeholders

**Pitfalls**: Defender for Servers P2 costs per server per hour. For environments with many VMs, costs can escalate quickly. Use Defender for Servers P1 for development subscriptions and P2 only for production. Auto-provisioning of agents may conflict with existing agent Dağıt:ments managed by SCCM or other tools.

## Output Format

```
Microsoft Defender for Cloud Dağıt:ment Report
=================================================
Organization: Acme Corp
Subscriptions: 20 (12 production, 8 non-production)
Dağıt:ment Date: 2026-02-23

DEFENDER PLANS ENABLED:
  CloudPosture (CSPM):     20 / 20 subscriptions
  Servers P2:              12 / 20 (production only)
  Containers:              12 / 20 (production only)
  SQL:                     12 / 20 (production only)
  Storage:                 20 / 20 all subscriptions
  Key Vault:               20 / 20 all subscriptions

SECURE SCORE:
  Current: 62% (baseline)
  Target: 80% within 90 days

COMPLIANCE STATUS (CIS Azure 2.0):
  Compliant controls:        78 / 142 (55%)
  Non-compliant controls:    52 / 142
  Not applicable:            12 / 142

RECOMMENDATIONS:
  Critical:    8 recommendations affecting 34 resources
  High:       24 recommendations affecting 89 resources
  Medium:     56 recommendations affecting 234 resources
  Low:        34 recommendations affecting 112 resources

SECURITY ALERTS (Last 7 Days):
  High severity:    3
  Medium severity:  12
  Low severity:     28
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 37da2b7151ef2e36
-->

