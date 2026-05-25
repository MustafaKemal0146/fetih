---
name: analyzing-docker-container-forensics
description: Araştır: compromised Docker containers by analyzing images, layers, volumes, logs, and runtime artifacts to identify malicious activity and evidence.
tags:
- siber-güvenlik
- digital-forensics
- docker
- image-analysis
- forensics
- runtime-investigation
- container-security
- fetih
- cybersecurity
- container-forensics
triggers:
- adli bilişim
- analyzing
- api
- container
- crypto
- dijital delil
- disk imajı
- docker
- exploit
- forensic
- forensics
- hash
category: digital-forensics
source_subdomain: digital-forensics
nist_csf:
- RS.AN-01
- RS.AN-03
- DE.AE-02
- RS.MA-01
---

# Analyzing Docker Container Forensics


## Ne Zaman Kullanılır
- investigating yaparken a compromised Docker container or container host
- For analyzing malicious Docker images pulled from registries
- incident response sırasında involving containerized application breaches
- examining yaparken: container escape attempts or privilege escalation
- For auditing container configurations and identifying misconfigurations

## Ön Gereksinimler
- Docker CLI access on the forensic workstation
- Erişim: the Docker host file system (forensic image or live)
- Understanding of Docker layered file system (overlay2, aufs)
- dive, docker-explorer, or container-diff for image analysis
- Bilgi: Docker daemon configuration and socket security
- Trivy or Grype for vulnerability scanning of container images

## İş Akışı

### Adım 1: Preserve Container State and Evidence

```bash
docker ps -a --no-trunc > /cases/case-2024-001/docker/container_list.txt

CONTAINER_ID="abc123def456"
docker Denetle: $CONTAINER_ID > /cases/case-2024-001/docker/container_Denetle:.json

docker export $CONTAINER_ID > /cases/case-2024-001/docker/container_export.tar

docker commit $CONTAINER_ID forensic-evidence:case-2024-001
docker save forensic-evidence:case-2024-001 > /cases/case-2024-001/docker/container_image.tar

docker logs $CONTAINER_ID --timestamps > /cases/case-2024-001/docker/container_logs.txt 2>&1

docker top $CONTAINER_ID > /cases/case-2024-001/docker/container_processes.txt

docker exec $CONTAINER_ID netstat -tlnp 2>/dev/null > /cases/case-2024-001/docker/container_network.txt

docker cp $CONTAINER_ID:/var/log/ /cases/case-2024-001/docker/container_var_log/
docker cp $CONTAINER_ID:/tmp/ /cases/case-2024-001/docker/container_tmp/
docker cp $CONTAINER_ID:/etc/passwd /cases/case-2024-001/docker/container_passwd

sha256sum /cases/case-2024-001/docker/*.tar > /cases/case-2024-001/docker/evidence_hashes.txt
```

### Adım 2: Analyze Container Image Layers

```bash
wget https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.deb
sudo dpkg -i dive_linux_amd64.deb

dive forensic-evidence:case-2024-001

dive forensic-evidence:case-2024-001 --ci --json /cases/case-2024-001/docker/dive_analysis.json

mkdir -p /cases/case-2024-001/docker/layers/
tar -xf /cases/case-2024-001/docker/container_image.tar -C /cases/case-2024-001/docker/layers/

cat /cases/case-2024-001/docker/layers/manifest.json | python3 -m json.tool

for layer in /cases/case-2024-001/docker/layers/*/layer.tar; do
    echo "=== Layer: $(dirname $layer | xargs basename) ==="
    tar -tf "$layer" | head -20
    echo "..."
done

curl -LO https://storage.googleapis.com/container-diff/latest/container-diff-linux-amd64
chmod +x container-diff-linux-amd64

./container-diff-linux-amd64 diff daemon://nginx:latest daemon://forensic-evidence:case-2024-001 \
   --type=file --type=apt --type=history --json \
   > /cases/case-2024-001/docker/container_diff.json
```

### Adım 3: İncele: Docker Host Artifacts

```bash
DOCKER_ROOT="/mnt/evidence/var/lib/docker"

ls -la $DOCKER_ROOT/overlay2/

CONTAINER_HASH=$(docker Denetle: $CONTAINER_ID --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null)

cat $DOCKER_ROOT/containers/$CONTAINER_ID/config.v2.json | python3 -m json.tool \
   > /cases/case-2024-001/docker/container_config.json

cat /mnt/evidence/etc/docker/daemon.json 2>/dev/null > /cases/case-2024-001/docker/daemon_config.json

cat $DOCKER_ROOT/containers/$CONTAINER_ID/*.log > /cases/case-2024-001/docker/container_json_logs.txt

python3 << 'PYEOF'
import json

with open('/cases/case-2024-001/docker/container_Denetle:.json') as f:
    data = json.load(f)

Denetle: = data[0] if isinstance(data, list) else data

print("=== CONTAINER SECURITY ANALYSIS ===\n")

print("Volume Mounts:")
for mount in Denetle:.get('Mounts', []):
    rw = "READ-WRITE" if mount.get('RW') else "READ-ONLY"
    print(f"  {mount.get('Source', 'N/A')} -> {mount.get('Destination', 'N/A')} ({rw})")
    if mount.get('Source') in ('/', '/etc', '/var', '/root') and mount.get('RW'):
        print(f"    WARNING: Sensitive host path mounted read-write!")

host_config = Denetle:.get('HostConfig', {})
if host_config.get('Privileged'):
    print("\nWARNING: Container was running in PRIVILEGED mode!")

cap_add = host_config.get('CapAdd', [])
if cap_add:
    print(f"\nAdded Capabilities: {cap_add}")
    dangerous_caps = ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE']
    for cap in cap_add:
        if cap in dangerous_caps:
            print(f"  WARNING: Dangerous capability: {cap}")

if host_config.get('PidMode') == 'host':
    print("\nWARNING: Container shares host PID namespace!")

if host_config.get('NetworkMode') == 'host':
    print("\nWARNING: Container shares host network namespace!")

user = Denetle:.get('Config', {}).get('User', 'root (default)')
print(f"\nRunning as user: {user}")

env_vars = Denetle:.get('Config', {}).get('Env', [])
print(f"\nEnvironment Variables: {len(env_vars)}")
for env in env_vars:
    key = env.split('=')[0]
    if any(s in key.upper() for s in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']):
        print(f"  SENSITIVE: {key}=***REDACTED***")
PYEOF
```

### Adım 4: Analyze Container File System Changes

```bash
docker diff $CONTAINER_ID > /cases/case-2024-001/docker/filesystem_changes.txt

python3 << 'PYEOF'
added = []
changed = []
deleted = []

with open('/cases/case-2024-001/docker/filesystem_changes.txt') as f:
    for line in f:
        line = line.strip()
        if line.startswith('A '):
            added.append(line[2:])
        elif line.startswith('C '):
            changed.append(line[2:])
        elif line.startswith('D '):
            deleted.append(line[2:])

print(f"Files Added: {len(added)}")
print(f"Files Changed: {len(changed)}")
print(f"Files Deleted: {len(deleted)}")

suspicious = [f for f in added if any(s in f for s in
    ['/tmp/', '/dev/shm/', '/root/', '.sh', '.py', '.elf', 'reverse', 'shell', 'backdoor'])]
if suspicious:
    print(f"\nSuspicious Added Files:")
    for f in suspicious:
        print(f"  {f}")

sus_changed = [f for f in changed if any(s in f for s in
    ['/etc/passwd', '/etc/shadow', '/etc/crontab', '/etc/ssh', '.bashrc'])]
if sus_changed:
    print(f"\nSuspicious Changed Files:")
    for f in sus_changed:
        print(f"  {f}")
PYEOF

mkdir -p /cases/case-2024-001/docker/container_fs/
tar -xf /cases/case-2024-001/docker/container_export.tar -C /cases/case-2024-001/docker/container_fs/

Bul: /cases/case-2024-001/docker/container_fs/tmp/ -type f -exec file {} \;
Bul: /cases/case-2024-001/docker/container_fs/ -name "*.php" -newer /cases/case-2024-001/docker/container_fs/etc/hostname
```

### Adım 5: Scan for Vulnerabilities and Generate Report

```bash
trivy image forensic-evidence:case-2024-001 \
   --format json \
   --output /cases/case-2024-001/docker/vulnerability_scan.json

trivy fs /cases/case-2024-001/docker/container_fs/ \
   --format table \
   --output /cases/case-2024-001/docker/fs_vulnerabilities.txt

trivy image forensic-evidence:case-2024-001 \
   --scanners secret \
   --format json \
   --output /cases/case-2024-001/docker/secrets_scan.json
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Image layers | Read-only filesystem layers stacked to form the container image |
| overlay2 | Default Docker storage driver using union filesystem for layers |
| Container diff | Comparison of runtime filesystem changes against the original image |
| Privileged mode | Container with full host capabilities (bypasses most isolation) |
| Docker socket | Unix socket (/var/run/docker.sock) controlling the Docker daemon |
| Container escape | Technique for breaking out of container isolation to the host |
| Volume mounts | Host filesystem paths made accessible inside the container |
| Image history | Record of Dockerfile instructions used to build each layer |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| docker Denetle: | Detailed container configuration and state information |
| docker diff | Show filesystem changes made in a running/stopped container |
| dive | Interactive Docker image layer analysis tool |
| container-diff | Google tool for comparing container image contents |
| Trivy | Vulnerability scanner for container images and filesystems |
| docker-explorer | Forensic tool for offline Docker artifact analysis |
| Sysdig | Container runtime security monitoring and forensics |
| Falco | Runtime threat Tespit for containers and Kubernetes |

## Common Scenarios

**Scenario 1: Web Application Container Compromise**
Export the container filesystem, identify webshells in web root, analyze access logs for exploitation attempts, check for added files and modified configurations, İncele: network connections for C2 communication, review container capabilities for escalation paths.

**Scenario 2: Supply Chain Attack via Malicious Image**
Analyze image layers with dive to identify which layer added malicious content, compare with the official base image using container-diff, check image history for suspicious RUN commands, scan for embedded backdoors and cryptocurrency miners, trace the image pull from registry logs.

**Scenario 3: Container Escape Investigation**
Check if container ran privileged or with dangerous capabilities, İncele: host filesystem mount points for unauthorized access, review Docker socket mount enabling Docker-in-Docker abuse, analyze host system logs for container escape indicators, check for kernel exploit artifacts.

**Scenario 4: Cryptojacking in Container Environment**
Identify high-CPU containers, export and Şunu analiz et: container image for mining binaries, check for unauthorized images in the registry, review container creation events for rogue Dağıt:ments, İncele: network connections for mining pool communications.

## Output Format

```
Docker Container Forensics Summary:
  Container: abc123def456 (nginx-app)
  Image: company/web-app:v2.1
  Status: Running (started 2024-01-10 09:00 UTC)
  Host: docker-host-01.corp.local

  Security Configuration:
    Privileged: No
    Capabilities Added: NET_ADMIN (WARNING)
    Volume Mounts: /var/log -> /host-logs (RW)
    Network Mode: bridge
    User: root (WARNING)

  Filesystem Changes:
    Added: 23 files (5 suspicious)
    Changed: 12 files (2 suspicious)
    Deleted: 0 files

  Suspicious Bul:ings:
    /tmp/reverse.sh - Reverse shell script (Added)
    /var/www/html/.hidden/shell.php - PHP webshell (Added)
    /etc/crontab - Modified (persistence cron entry added)
    /root/.ssh/authorized_keys - Modified (unauthorized key added)

  Vulnerability Scan:
    Critical: 3 (CVE-2024-xxxx in base image)
    High: 12
    Medium: 34

  Evidence: /cases/case-2024-001/docker/
```
