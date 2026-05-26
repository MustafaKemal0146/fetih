---
name: implementing-google-workspace-sso-configuration
description: Configure SAML 2.0 single sign-on for Google Workspace with a third-party identity provider, enabling centralized authentication and enforcing organization-wide access policies.
tags:
- cybersecurity
- identity-access-management
- saml
- fetih
- authentication
- sso
- google-workspace
- identity-provider
- siber-güvenlik
- federation
triggers:
- authentication
- certificate
- cloud
- configuration
- dns
- email
- endpoint
- google
- http
- implementing
- log
- network
category: identity-access-management
source_subdomain: identity-access-management
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
adapted_for: fetih
---

# Implementing Google Workspace Sso Configuration


## Genel Bakış

Single Sign-On (SSO) for Google Workspace allows organizations to authenticate users through their existing identity provider (IdP) such as Okta, Azure AD (Microsoft Entra ID), or ADFS, rather than managing separate Google passwords. This is implemented using SAML 2.0 protocol where Google Workspace acts as the Service Provider (SP) and the organization's IdP handles authentication. SSO centralizes credential management, enforces MFA policies at the IdP, and enables immediate access revocation when users leave the organization.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing google workspace sso configuration capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Google Workspace Business, Enterprise, or Education edition
- Super Admin Erişim: Google Admin Console
- Identity Provider with SAML 2.0 support (Okta, Azure AD, ADFS, Ping Identity)
- IdP signing certificate (X.509 PEM format, RSA or DSA)
- DNS verification for the Google Workspace domain

## Core Concepts

### SAML 2.0 SSO Flow

```
User navigates to Google Workspace app (Gmail, Drive, etc.)
        │
        ├── Google checks: Is SSO configured for this domain?
        │
        ├── YES → Redirect user to IdP Sign-In Page URL
        │          (SAML AuthnRequest sent via browser redirect)
        │
        ├── User authenticates at IdP (credentials + MFA)
        │
        ├── IdP generates SAML Response with signed assertion
        │
        ├── Browser POSTs SAML Response to Google ACS URL:
        │   https://www.google.com/a/{domain}/acs
        │
        ├── Google validates SAML signature against uploaded certificate
        │
        └── User is granted Erişim: Google Workspace
```

### Key SAML Parameters

| Parameter | Value |
|-----------|-------|
| ACS URL | `https://www.google.com/a/{your-domain}/acs` |
| Entity ID | `google.com/a/{your-domain}` or `google.com` |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| NameID Value | User's primary Google Workspace email |
| Binding | HTTP-POST (for ACS), HTTP-Redirect (for SSO URL) |

## İş Akışı

### Adım 1: Prepare the Identity Provider

**For Okta:**
1. Şuraya git: Applications > Add Application > Search "Google Workspace"
2. Şunu yapılandır: Google Workspace app with your domain
3. Assign users/groups to the application
4. Download the IdP metadata or note: SSO URL, Entity ID, Certificate

**For Azure AD (Microsoft Entra ID):**
1. Şuraya git: Enterprise Applications > New Application > Google Cloud/Workspace
2. Configure Single sign-on > SAML
3. Set Basic SAML Configuration:
   - Identifier (Entity ID): `google.com`
   - Reply URL (ACS): `https://www.google.com/a/{your-domain}/acs`
   - Sign on URL: `https://www.google.com/a/{your-domain}/ServiceLogin`
4. Download Federation Metadata XML or Certificate (Base64)

**For ADFS:**
1. Add Relying Party Trust using federation metadata
2. Configure claim rules to pass NameID as email address
3. Export the token-signing certificate

### Adım 2: Configure Google Workspace SSO

1. Sign in to Google Admin Console (admin.google.com) as Super Admin
2. Şuraya git: Security > Authentication > SSO with third-party IdP
3. Click "Add SSO profile" or Şunu yapılandır: default profile

**Third-Party SSO Profile Settings:**

| Setting | Value |
|---------|-------|
| Kur: SSO with third-party IdP | Enabled |
| Sign-in page URL | IdP's SAML SSO endpoint (e.g., `https://idp.example.com/sso/saml`) |
| Sign-out page URL | IdP's logout URL (e.g., `https://idp.example.com/slo`) |
| Change password URL | IdP's password change URL |
| Verification certificate | Upload IdP's X.509 signing certificate |
| Use a domain-specific issuer | Enabled (uses `google.com/a/{domain}` as entity ID) |

### Adım 3: Assign SSO Profile to Users

SSO profiles can be applied at different scopes:

```
Organization-wide (all users)
    │
    ├── Org Unit level (specific departments)
    │   ├── Engineering OU → SSO via Okta
    │   ├── Marketing OU → SSO via Azure AD
    │   └── Contractors OU → SSO via specific IdP
    │
    └── Group level (specific security groups)
        └── VPN Users → SSO with additional MFA
```

1. Şuraya git: Security > Authentication > SSO with third-party IdP
2. Select the SSO profile to assign
3. Choose organizational units or groups
4. Save and wait for propagation (up to 24 hours, typically minutes)

### Adım 4: Configure Network Masks (Optional)

Network masks control when SSO is enforced based on the user's IP:

- If the user's IP matches a network mask, they use Google's sign-in page
- If the user's IP does NOT match, they are redirected to the IdP

This is useful for allowing direct Google login from corporate network while enforcing SSO for external access.

### Adım 5: Test SSO

1. Open an incognito browser window
2. Şuraya git: `https://mail.google.com/a/{your-domain}`
3. Verify redirect to IdP sign-in page
4. Authenticate at the IdP
5. Verify successful redirect back to Google Workspace
6. Test sign-out flow redirects to IdP logout page
7. Test with user not assigned in IdP (should fail)

## Doğrulama Checklist

- [ ] IdP SAML application configured with correct ACS URL and Entity ID
- [ ] IdP signing certificate uploaded to Google Admin Console
- [ ] SSO profile assigned to target organizational units/groups
- [ ] SAML assertion includes correct NameID (email format)
- [ ] MFA enforced at IdP for all Google Workspace users
- [ ] Sign-out URL configured to terminate IdP session
- [ ] Network masks configured if internal/external access differs
- [ ] Break-glass Super Admin accounts bypass SSO (use Google auth)
- [ ] SSO tested with multiple user types (admin, standard, contractor)
- [ ] SAML response signature validated successfully
- [ ] Error handling tested (expired cert, invalid user, clock skew)

## References

- [Google Workspace SSO Configuration Guide](https://support.google.com/a/answer/12032922)
- [Kur: Custom SAML App - Google](https://support.google.com/a/answer/6087519)
- [Okta Google Workspace SAML Guide](https://saml-doc.okta.com/SAML_Docs/How-to-Enable-SAML-2.0-in-Google-Apps.html)
- [SAML 2.0 Technical Overview - OASIS](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: d25c76f2fab65f45
-->

