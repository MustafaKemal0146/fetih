---
name: analyzing-active-directory-acl-abuse
description: tespit etmedangerous ACL misconfigurations in Active Directory using ldap3 to identify GenericAll, WriteDACL, and WriteOwner abuse paths
tags:
- ldap
- identity-security
- fetih
- privilege-escalation
- cybersecurity
- acl-abuse
- active-directory
- siber-güvenlik
- identity-access-management
triggers:
- abuse
- active
- analyzing
- authentication
- directory
- incident
- network
- password
- threat
category: identity-access-management
source_subdomain: identity-security
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.AA-06
---

# Analyzing Active Directory Acl Abuse


## Genel Bakış

Active Directory Access Control Lists (ACLs) define permissions on AD objects through Discretionary Access Control Lists (DACLs) containing Access Control Entries (ACEs). Misconfigured ACEs can grant non-privileged users dangerous permissions such as GenericAll (full control), WriteDACL (modify permissions), WriteOwner (take ownership), and GenericWrite (modify attributes) on sensitive objects like Domain Admins groups, domain controllers, or GPOs.

bu skill uses the ldap3 Python library to connect to a Domain Controller, query objects with their nTSecurityDescriptor attribute, parse the binary security descriptor into SDDL (Security Descriptor Definition Language) format, and identify ACEs that grant dangerous permissions to non-administrative principals. These misconfigurations are the basis for ACL-based attack paths discovered by tools like BloodHound.


## Ne Zaman Kullanılır

- investigating yaparken security incidents that require analyzing active directory acl abuse
- building yaparken Tespit rules or threat hunting queries for this domain
- SOC yaparken: analysts need structured procedures for this analysis type
- validating yaparken security monitoring coverage for related attack techniques

## Ön Gereksinimler

- Python 3.9 or later with ldap3 library (`pip install ldap3`)
- Domain user credentials with read Erişim: AD objects
- Network connectivity to Domain Controller on port 389 (LDAP) or 636 (LDAPS)
- Understanding of Active Directory security model and SDDL format

## Adımlar

1. **Connect to Domain Controller**: Establish an LDAP connection using ldap3 with NTLM or simple authentication. Use LDAPS (port 636) for encrypted connections in production.

2. **Query target objects**: Search the target OU or entire domain for objects including users, groups, computers, and OUs. Request the `nTSecurityDescriptor`, `distinguishedName`, `objectClass`, and `sAMAccountName` attributes.

3. **Parse security descriptors**: Convert the binary nTSecurityDescriptor into its SDDL string representation. Parse each ACE in the DACL to Şunu çıkar: trustee SID, access mask, and ACE type (allow/deny).

4. **Resolve SIDs to principals**: Map security identifiers (SIDs) to human-readable account names using LDAP lookups against the domain. Identify well-known SIDs for built-in groups.

5. **Check for dangerous permissions**: Compare each ACE's access mask against dangerous permission bitmasks: GenericAll (0x10000000), WriteDACL (0x00040000), WriteOwner (0x00080000), GenericWrite (0x40000000), and WriteProperty for specific extended rights.

6. **Filter non-admin trustees**: Exclude expected administrative trustees (Domain Admins, Enterprise Admins, SYSTEM, Administrators) and flag ACEs where non-privileged users or groups hold dangerous permissions.

7. **Map attack paths**: For each Bul:ing, Şunu belgele: potential attack chain (e.g., GenericAll on user allows password reset, WriteDACL on group allows adding self to group).

8. **Generate remediation report**: Output a JSON report with all dangerous ACEs, affected objects, non-admin trustees, and recommended remediation steps.

## Expected Output

```json
{
  "domain": "corp.example.com",
  "objects_scanned": 1247,
  "dangerous_aces_found": 8,
  "Bul:ings": [
    {
      "severity": "critical",
      "target_object": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
      "target_type": "group",
      "trustee": "CORP\\helpdesk-team",
      "permission": "GenericAll",
      "access_mask": "0x10000000",
      "ace_type": "ACCESS_ALLOWED",
      "attack_path": "GenericAll on Domain Admins group allows adding arbitrary members",
      "remediation": "Remove GenericAll ACE for helpdesk-team on Domain Admins"
    }
  ]
}
```
