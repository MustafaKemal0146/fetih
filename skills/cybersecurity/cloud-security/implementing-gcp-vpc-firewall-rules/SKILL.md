---
name: implementing-gcp-vpc-firewall-rules
description: Implementing and auditing GCP VPC firewall rules to enforce network segmentation, restrict ingress and egress traffic, apply hierarchical firewall policies across the organization, and monitor
  firewall rule effectiveness using VPC Flow Logs.
tags:
- vpc
- firewall-rules
- gcp
- network-security
- segmentation
- fetih
- cloud-security
- cybersecurity
- siber-güvenlik
triggers:
- AWS
- Azure
- GCP
- api
- bulut güvenliği
- cloud
- cloud security
- dns
- firewall
- forensic
- http
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

# Implementing Gcp Vpc Firewall Rules


## Ne Zaman Kullanılır

- Dağıt:ing yaparken new GCP workloads that require network-level access controls
- auditing yaparken existing firewall configurations for overly permissive rules
- implementing yaparken zero trust network segmentation within GCP VPC networks
- responding yaparken to Security Command Center Bul:ings about open firewall rules
- building yaparken hierarchical firewall policies across a GCP organization

**Kullanma:** for application-layer filtering (use Cloud Armor WAF), for DNS-based filtering (use Cloud DNS response policies), or for VPN/interconnect traffic filtering without understanding that VPC firewall rules apply to traffic within the VPC.

## Ön Gereksinimler

- GCP project with Compute Engine API enabled
- IAM roles: `roles/compute.securityAdmin` for firewall management, `roles/compute.networkViewer` for auditing
- Organization Admin role for hierarchical firewall policies
- gcloud CLI authenticated with appropriate permissions
- VPC Flow Logs enabled on target subnets for monitoring

## İş Akışı

### Adım 1: Audit Existing Firewall Rules for Security Gaps

Enumerate all firewall rules and identify overly permissive configurations.

```bash
gcloud compute firewall-rules list \
  --format="table(name, network, direction, priority, allowed[].map().firewall_rule().list():label=ALLOWED, sourceRanges, targetTags)"

gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, priority, targetTags)" \
  --sort-by=priority

gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"

gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"

gcloud compute firewall-rules list \
  --filter="disabled=true" \
  --format="table(name, network, direction)"
```

### Adım 2: Create Restrictive Ingress Firewall Rules

Implement least-privilege ingress rules using network tags and service accounts for targeting.

```bash
gcloud compute firewall-rules Şunu oluştur:llow-https-web \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=web-server \
  --priority=1000 \
  --description="Allow HTTPS to web servers from internet"

gcloud compute firewall-rules Şunu oluştur:llow-ssh-bastion \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=10.0.1.0/24 \
  --target-tags=ssh-allowed \
  --priority=1000 \
  --description="Allow SSH only from bastion subnet"

gcloud compute firewall-rules Şunu oluştur:llow-app-to-db \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-tags=app-server \
  --target-tags=db-server \
  --priority=1000 \
  --description="Allow PostgreSQL from app tier to database tier"

gcloud compute firewall-rules Şunu oluştur:llow-api-internal \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-service-accounts=api-client@project.iam.gserviceaccount.com \
  --target-service-accounts=api-server@project.iam.gserviceaccount.com \
  --priority=1000
```

### Adım 3: Implement Egress Restrictions

Configure egress firewall rules to control outbound traffic and prevent data exfiltration.

```bash
gcloud compute firewall-rules create deny-all-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=DENY \
  --rules=all \
  --destination-ranges=0.0.0.0/0 \
  --priority=65534 \
  --description="Default deny all egress traffic"

gcloud compute firewall-rules Şunu oluştur:llow-google-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=199.36.153.4/30 \
  --priority=1000 \
  --description="Allow HTTPS to Google APIs restricted VIP"

gcloud compute firewall-rules Şunu oluştur:llow-dns-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=udp:53,tcp:53 \
  --destination-ranges=169.254.169.254/32,8.8.8.8/32,8.8.4.4/32 \
  --priority=1000 \
  --description="Allow DNS resolution to metadata and Google DNS"

gcloud compute firewall-rules Şunu oluştur:llow-external-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=PARTNER_CIDR/32 \
  --target-tags=api-client \
  --priority=1000
```

### Adım 4: Dağıt: Hierarchical Firewall Policies

Create organization and folder-level firewall policies that apply across all projects.

```bash
gcloud compute firewall-policies create \
  --organization=ORG_ID \
  --short-name=org-security-policy \
  --description="Organization-wide security firewall policy"

gcloud compute firewall-policies rules create 100 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=deny \
  --src-ip-ranges=THREAT_INTEL_CIDR_1,THREAT_INTEL_CIDR_2 \
  --layer4-configs=all \
  --description="Block known malicious IPs organization-wide"

gcloud compute firewall-policies rules create 200 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=allow \
  --src-ip-ranges=0.0.0.0/0 \
  --layer4-configs=tcp:443 \
  --description="Allow only HTTPS from external sources"

gcloud compute firewall-policies associations create \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID
```

### Adım 5: Enable VPC Flow Logs for Monitoring

Configure VPC Flow Logs to monitor traffic patterns and validate firewall rule effectiveness.

```bash
gcloud compute networks subnets update production-subnet \
  --region=us-central1 \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0 \
  --logging-metadata=include-all

gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.disposition="DENIED"
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=50 --format=json

gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.rule_details.reference:"/firewall-rules/default-allow-"
' --limit=100 --format="table(jsonPayload.connection.src_ip,jsonPayload.connection.dest_ip,jsonPayload.connection.dest_port)"

gcloud logging sinks create vpc-flow-bq \
  bigquery.googleapis.com/projects/PROJECT/datasets/vpc_flow_logs \
  --log-filter='resource.type="gce_subnetwork"'
```

## Key Concepts

| Term | Definition |
|------|------------|
| VPC Firewall Rule | Stateful network-level access control that allows or denies traffic to and from VM instances based on IP ranges, protocols, ports, and tags |
| Hierarchical Firewall Policy | Organization or folder-level firewall policy that is evaluated before VPC-level rules and applies across all child projects |
| Network Tag | Label applied to VM instances that Belirle:s which firewall rules apply, used for targeting ingress and egress rules |
| Service Account Firewall Rule | Firewall rule that targets instances based on their attached service account, providing more secure targeting than mutable network tags |
| VPC Flow Logs | Network telemetry captured at the subnet level that records traffic metadata for monitoring, forensics, and firewall rule validation |
| Implied Rules | Default GCP firewall rules that allow egress to all destinations and deny ingress from all sources, with lowest priority (65535) |

## Tools & Systems

- **gcloud compute firewall-rules**: CLI commands for creating, listing, and managing VPC firewall rules in GCP
- **Hierarchical Firewall Policies**: Organization and folder-level policies enforcing security controls across all projects
- **VPC Flow Logs**: Subnet-level traffic logging for monitoring, troubleshooting, and validating firewall effectiveness
- **Cloud Logging**: Query engine for analyzing VPC Flow Logs and firewall rule hit counts
- **Security Command Center**: GCP-native security platform with Bul:ings for overly permissive firewall configurations

## Common Scenarios

### Scenario: Locking Down a Production VPC After Discovery of Overly Permissive Rules

**Context**: A security audit reveals that the production VPC has default-allow rules permitting SSH from `0.0.0.0/0` and unrestricted egress. SCC reports 14 firewall Bul:ings.

**Approach**:
1. Enumerate all existing rules with `gcloud compute firewall-rules list` and categorize by risk
2. Enable VPC Flow Logs on all subnets to capture baseline traffic patterns for 7 days
3. Analyze flow logs to identify legitimate traffic that needs explicit allow rules
4. Create targeted ingress rules for each application tier (web: 443, app: 8080, db: 5432)
5. Replace the SSH-from-anywhere rule with SSH-from-bastion-subnet-only
6. Implement default-deny egress and add explicit allow rules for required outbound destinations
7. Delete the overly permissive default-allow rules after verifying applications function correctly

**Pitfalls**: Deleting firewall rules without understanding traffic patterns causes outages. Always enable flow logs and analyze traffic before removing rules. Network tags can be added by anyone with compute.instances.setTags permission, making them less secure than service-account-based targeting for critical rules.

## Output Format

```
GCP VPC Firewall Audit Report
================================
Project: production-project
VPC Network: production-vpc
Audit Date: 2026-02-23

RULE INVENTORY:
  Total firewall rules: 34
  Ingress rules: 22
  Egress rules: 12
  Disabled rules: 3

CRITICAL Bul:INGS:
[FW-001] SSH Open to Internet
  Rule: default-allow-ssh
  Source: 0.0.0.0/0 -> tcp:22
  Target: All instances (no tags)
  Priority: 65534
  Remediation: Restrict to bastion subnet CIDR

[FW-002] No Egress Restrictions
  Issue: Only implied allow-all-egress rule exists
  Risk: No controls on outbound data exfiltration
  Remediation: Add default-deny egress and explicit allow rules

REMEDIATION ACTIONS COMPLETED:
  Rules deleted: 3 (overly permissive defaults)
  Rules created: 8 (targeted allow rules)
  Egress deny rule: Created at priority 65534
  Flow logs enabled: 6 subnets
```

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: ac49d4d20d14412e
-->

