---
name: hardening-docker-daemon-configuration
description: Harden the Docker daemon by configuring daemon.json with user namespace remapping, TLS authentication, rootless mode, and CIS benchmark controls.
tags:
- rootless
- docker
- cis-benchmark
- container-security
- userns-remap
- daemon-hardening
- fetih
- cybersecurity
- siber-güvenlik
triggers:
- api
- certificate
- configuration
- container
- daemon
- dns
- docker
- hardening
- http
- log
- network
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
---

# Hardening Docker Daemon Configuration


## Genel Bakış

The Docker daemon (`dockerd`) runs with root privileges and controls all container operations. Hardening its configuration through `/etc/docker/daemon.json`, TLS certificates, user namespace remapping, and network restrictions is essential to prevent privilege escalation, lateral movement, and container breakout attacks.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring hardening docker daemon configuration capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- Docker Engine 24.0+ installed
- Root or sudo Erişim: the Docker host
- OpenSSL for TLS certificate generation
- Understanding of Linux namespaces and cgroups

## Core Hardened daemon.json

```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "5"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 32768
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 4096,
      "Soft": 2048
    }
  },
  "seccomp-profile": "/etc/docker/seccomp/default.json",
  "default-address-pools": [
    {
      "base": "172.17.0.0/16",
      "size": 24
    }
  ],
  "iptables": true,
  "ip-forward": true,
  "ip-masq": true,
  "experimental": false,
  "metrics-addr": "127.0.0.1:9323",
  "max-concurrent-downloads": 3,
  "max-concurrent-uploads": 5,
  "default-runtime": "runc",
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": ["--platform=ptrace"]
    }
  }
}
```

## Setting-by-Setting Explanation

### Disable Inter-Container Communication (ICC)

```json
{
  "icc": false
}
```

Prevents containers on the default bridge network from communicating. Each container must use explicit `--link` or user-defined networks with published ports.

### Enable User Namespace Remapping

```json
{
  "userns-remap": "default"
}
```

Maps container root (UID 0) to a high unprivileged UID on the host. This prevents a container breakout from gaining root on the host.

```bash
cat /etc/subuid

cat /etc/subgid

docker run --rm alpine id
```

### Disable New Privilege Escalation

```json
{
  "no-new-privileges": true
}
```

Prevents container processes from gaining additional privileges via setuid/setgid binaries or capability escalation.

### Enable Live Restore

```json
{
  "live-restore": true
}
```

Keeps containers running during daemon downtime, enabling daemon upgrades without container restart.

### Disable Userland Proxy

```json
{
  "userland-proxy": false
}
```

Uses iptables rules instead of docker-proxy for port forwarding, reducing attack surface and improving performance.

## TLS Configuration for Remote Docker API

### Generate CA and Server Certificates

```bash
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem \
  -subj "/CN=Docker CA"

openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=docker-host" -sha256 -new -key server-key.pem -out server.csr

echo "subjectAltName = DNS:docker-host,IP:10.0.0.5,IP:127.0.0.1" > extfile.cnf
echo "extendedKeyUsage = serverAuth" >> extfile.cnf

openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -extfile extfile.cnf

openssl genrsa -out key.pem 4096
openssl req -subj "/CN=client" -new -key key.pem -out client.csr
echo "extendedKeyUsage = clientAuth" > extfile-client.cnf
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -extfile extfile-client.cnf

chmod 0400 ca-key.pem key.pem server-key.pem
chmod 0444 ca.pem server-cert.pem cert.pem

sudo mkdir -p /etc/docker/tls
sudo cp ca.pem server-cert.pem server-key.pem /etc/docker/tls/
```

### Configure daemon.json for TLS

```json
{
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/tls/ca.pem",
  "tlscert": "/etc/docker/tls/server-cert.pem",
  "tlskey": "/etc/docker/tls/server-key.pem",
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"]
}
```

### Client Connection

```bash
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=tcp://docker-host:2376 version
```

## Docker Socket Protection

```bash
sudo chown root:docker /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock

sudo auditctl -w /var/run/docker.sock -k docker-socket

```

## Rootless Docker

```bash
curl -fsSL https://get.docker.com/rootless | sh

export PATH=$HOME/bin:$PATH
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock

systemctl --user start docker
systemctl --user enable docker

docker info | grep -i rootless
```

## Content Trust (Image Signing)

```bash
export DOCKER_CONTENT_TRUST=1

docker pull library/alpine:3.18

docker trust sign myregistry/myapp:1.0
```

## Seccomp Profile

```bash
docker info --format '{{.SecurityOptions}}'

docker run --security-opt seccomp=/etc/docker/seccomp/custom.json alpine

docker Denetle: --format='{{.HostConfig.SecurityOpt}}' container_name
```

## AppArmor Profile

```bash
sudo aa-status

docker run --security-opt apparmor=docker-custom alpine

sudo apparmor_parser -r /etc/apparmor.d/docker-custom
```

## Verification Commands

```bash
docker info

docker info --format '{{.SecurityOptions}}'

docker network Denetle: bridge --format '{{.Options}}'

docker run --rm --net host --pid host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/etc:ro \
  docker/docker-bench-security
```

## En İyi Uygulamalar

1. **Never expose Docker daemon without TLS** - Always use `--tlsverify` for remote access
2. **Enable user namespace remapping** - Map container root to unprivileged host UID
3. **Disable ICC** - Prevent default bridge network container-to-container communication
4. **Use rootless mode** - Run Docker daemon as non-root where possible
5. **Enable content trust** - Only pull signed images
6. **Configure log rotation** - Prevent log files from filling disk
7. **Use seccomp profiles** - Restrict syscalls available to containers
8. **Audit Docker socket** - Monitor Erişim: /var/run/docker.sock
9. **Run Docker Bench regularly** - Automate CIS benchmark checks
10. **Keep Docker updated** - Apply security patches promptly
