---
name: Dağıt:ing-tailscale-for-zero-trust-vpn
description: Dağıt: and configure Tailscale as a WireGuard-based zero trust mesh VPN with identity-aware access controls, ACLs, and exit nodes for secure peer-to-peer connectivity.
tags:
- headscale
- mesh-vpn
- tailscale
- zero-trust-architecture
- acl
- ztna
- fetih
- peer-to-peer
- cybersecurity
- zero-trust
- identity-aware
- siber-güvenlik
- wireguard
triggers:
- api
- authentication
- container
- Dağıt:ing
- dns
- http
- log
- network
- sql
- tailscale
- trust
- web
category: zero-trust-architecture
source_subdomain: zero-trust-architecture
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
adapted_for: fetih
---

# Dağıt:ing Tailscale for Zero Trust Vpn


## Genel Bakış

Tailscale is a zero trust mesh VPN built on WireGuard that creates encrypted peer-to-peer connections between devices without requiring traditional VPN servers or complex network configuration. Every connection in a Tailscale network (tailnet) is end-to-end encrypted using WireGuard's Noise protocol framework with Curve25519 key exchange. Tailscale implements zero trust networking by authenticating every connection request through identity providers, enforcing granular Access Control Lists (ACLs), and supporting features like exit nodes, subnet routers, MagicDNS, and Tailscale SSH. For organizations preferring self-hosted infrastructure, Headscale provides an open-source implementation of the Tailscale control server.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring Dağıt:ing tailscale for zero trust vpn capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Identity provider (Okta, Azure AD, Google Workspace, GitHub, or OIDC-compatible)
- Devices running supported OS (Linux, Windows, macOS, iOS, Android, FreeBSD)
- Administrative Erişim: configure DNS and firewall rules
- Understanding of WireGuard protocol fundamentals
- Network planning documentation for subnet routing requirements

## Architecture

```
                    Tailscale Coordination Server
                    (or self-hosted Headscale)
                           |
                    Key Distribution
                    & NAT Traversal
                           |
         +-----------------+-----------------+
         |                 |                 |
    +----+----+      +----+----+      +----+----+
    | Node A  |<---->| Node B  |<---->| Node C  |
    | (Linux) |      | (macOS) |      |(Windows)|
    +---------+      +---------+      +---------+
    WireGuard         WireGuard        WireGuard
    Encrypted         Encrypted        Encrypted
    P2P Tunnel        P2P Tunnel       P2P Tunnel

    Each node connects directly to every other node.
    DERP relay servers used only when direct P2P fails.
```

## Kurulum and Setup

### Linux Installation

```bash
curl -fsSL https://tailscale.com/install.sh | sh

sudo tailscale up

tailscale status

tailscale ip -4
tailscale ip -6
```

### Windows / macOS Installation

```bash
brew install --cask tailscale

```

### Docker Dağıt:ment

```yaml
services:
  tailscale:
    image: tailscale/tailscale:latest
    container_name: tailscale
    hostname: my-service
    environment:
      - TS_AUTHKEY=tskey-auth-xxxxx  # Pre-auth key
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_EXTRA_ARGS=--advertise-tags=tag:container
    volumes:
      - tailscale-state:/var/lib/tailscale
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - net_admin
      - sys_module
    restart: unless-stopped

volumes:
  tailscale-state:
```

### Kubernetes Dağıt:ment

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tailscale-auth
  namespace: tailscale
type: Opaque
stringData:
  TS_AUTHKEY: "tskey-auth-xxxxx"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: tailscale
  namespace: tailscale
spec:
  selector:
    matchLabels:
      app: tailscale
  template:
    metadata:
      labels:
        app: tailscale
    spec:
      containers:
      - name: tailscale
        image: tailscale/tailscale:latest
        env:
        - name: TS_AUTHKEY
          valueFrom:
            secretKeyRef:
              name: tailscale-auth
              key: TS_AUTHKEY
        - name: TS_KUBE_SECRET
          value: tailscale-state
        - name: TS_USERSPACE
          value: "true"
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
```

## Access Control Lists (ACLs)

Tailscale ACLs define who can access what within your tailnet using a declarative JSON format. The default policy is deny-all, making it zero trust by design.

```json
{
  "acls": [
    // Engineering team can access development servers
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:dev-server:*"]
    },
    // SRE team can access production infrastructure
    {
      "action": "accept",
      "src": ["group:sre"],
      "dst": ["tag:production:22,443,8080"]
    },
    // Database access restricted to backend services
    {
      "action": "accept",
      "src": ["tag:backend"],
      "dst": ["tag:database:5432,3306,27017"]
    },
    // All employees can access internal tools
    {
      "action": "accept",
      "src": ["group:employees"],
      "dst": ["tag:internal-tools:443"]
    }
  ],

  "groups": {
    "group:engineering": ["user@company.com", "dev@company.com"],
    "group:sre": ["sre@company.com", "oncall@company.com"],
    "group:employees": ["autogroup:members"]
  },

  "tagOwners": {
    "tag:dev-server": ["group:engineering"],
    "tag:production": ["group:sre"],
    "tag:backend": ["group:sre"],
    "tag:database": ["group:sre"],
    "tag:internal-tools": ["group:sre"],
    "tag:container": ["group:sre"]
  },

  "ssh": [
    {
      "action": "check",
      "src": ["group:sre"],
      "dst": ["tag:production"],
      "users": ["root", "admin"]
    },
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:dev-server"],
      "users": ["autogroup:nonroot"]
    }
  ],

  "nodeAttrs": [
    {
      "target": ["autogroup:members"],
      "attr": ["funnel:deny"]
    }
  ]
}
```

## Exit Nodes and Subnet Routing

### Configure Exit Node

```bash
sudo tailscale up --advertise-exit-node

sudo tailscale up --exit-node=<exit-node-ip>

curl ifconfig.me  # Should show exit node's public IP
```

### Subnet Router Configuration

```bash
sudo tailscale up --advertise-routes=10.0.0.0/24,192.168.1.0/24

echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

sudo tailscale up --accept-routes
```

## Tailscale SSH (Zero Trust SSH)

Tailscale SSH replaces traditional SSH key management with identity-based access.

```bash
sudo tailscale up --ssh

ssh user@hostname  # Authenticates via Tailscale identity

```

## MagicDNS Configuration

```bash
ping my-server  # Resolves via MagicDNS

```

## Self-Hosted with Headscale

```bash
wget https://github.com/juanfont/headscale/releases/latest/download/headscale_linux_amd64
chmod +x headscale_linux_amd64
sudo mv headscale_linux_amd64 /usr/local/bin/headscale

sudo mkdir -p /etc/headscale
sudo headscale generate config > /etc/headscale/config.yaml


sudo headscale serve

headscale users create myorg
headscale preauthkeys create --user myorg --reusable --expiration 24h

tailscale up --login-server https://headscale.example.com
```

## Security Hardening

### Key Expiry and Rotation

```bash

sudo tailscale up --authkey=tskey-auth-xxxxx

```

### Device Authorization

```json
{
  "nodeAttrs": [
    {
      "target": ["autogroup:members"],
      "attr": [
        "mullvad:deny",
        "funnel:deny"
      ]
    }
  ],
  "autoApprovers": {
    "routes": {
      "10.0.0.0/24": ["group:sre"],
      "192.168.0.0/16": ["group:sre"]
    },
    "exitNode": ["group:sre"]
  }
}
```

### Network Lock (Tailnet Lock)

```bash
tailscale lock init

tailscale lock add nodekey:xxxxx

```

## Monitoring and Observability

```bash
tailscale status --json | jq '.Peer | to_entries[] | {name: .value.HostName, online: .value.Online, os: .value.OS}'

tailscale ping <peer-ip>

tailscale netcheck

```

## Integration Patterns

### Service Mesh Integration

```bash

```

### CI/CD Pipeline Integration

```bash
export TS_AUTHKEY=tskey-auth-xxxxx-ephemeral
tailscale up --authkey=$TS_AUTHKEY --hostname=ci-runner-$CI_JOB_ID

```

## References

- [Tailscale Documentation](https://tailscale.com/kb/)
- [How Tailscale Works](https://tailscale.com/blog/how-tailscale-works)
- [Tailscale ACL Documentation](https://tailscale.com/kb/1018/acls/)
- [Headscale - Open Source Control Server](https://github.com/juanfont/headscale)
- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: e4fd6b767f57a192
-->

