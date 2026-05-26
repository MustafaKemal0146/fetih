---
name: performing-docker-bench-security-assessment
description: Docker Bench for Security is an open-source script that checks dozens of common best practices around Dağıt:ing Docker containers in production. Based on the CIS Docker Benchmark, it audits
  host confi
tags:
- security
- docker
- container-security
- fetih
- assessment
- cybersecurity
- siber-güvenlik
- containers
- CIS-benchmark
triggers:
- assessment
- bench
- container
- docker
- http
- incident
- log
- network
- performing
- security
category: container-security
source_subdomain: container-security
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
adapted_for: fetih
---

# Performing Docker Bench Security Assessment


## Genel Bakış

Docker Bench for Security is an open-source script that checks dozens of common best practices around Dağıt:ing Docker containers in production. Based on the CIS Docker Benchmark, it audits host configuration, Docker daemon settings, container images, runtime configurations, and security operations to Şunu üret: compliance report with pass/fail/warn results.


## Ne Zaman Kullanılır

- conducting yaparken security assessments that involve performing docker bench security assessment
- following yaparken: incident response procedures for related security events
- performing yaparken scheduled security testing or auditing activities
- validating yaparken security controls through hands-on testing

## Ön Gereksinimler

- Docker Engine installed and running
- Root or sudo access on Docker host
- Docker Bench Security script or container image

## İş Akışı

### Adım 1: Run Docker Bench Security

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security

docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security -l /dev/stdout 2>/dev/null | tee docker-bench-results.json

docker run --rm --net host --pid host --userns host \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker/docker-bench-security -c container_images,container_runtime
```

### Adım 2: Interpret Results

```
[INFO] 1 - Host Configuration
[PASS] 1.1.1 - Ensure a separate partition for containers has been created
[WARN] 1.1.2 - Ensure only trusted users are allowed to control Docker daemon
[PASS] 1.1.3 - Ensure auditing is configured for the Docker daemon

[INFO] 2 - Docker daemon configuration
[FAIL] 2.1 - Run the Docker daemon as a non-root user
[PASS] 2.2 - Ensure network traffic is restricted between containers on the default bridge
```

### Adım 3: Remediate Common Failures

```bash
echo '{"icc": false}' | sudo tee /etc/docker/daemon.json

echo '{"no-new-privileges": true}' | sudo tee -a /etc/docker/daemon.json


sudo systemctl restart docker
```

### Adım 4: Automate Scheduled Assessments

```yaml
services:
  bench-security:
    image: docker/docker-bench-security
    network_mode: host
    pid: host
    userns_mode: host
    cap_add:
      - audit_control
    volumes:
      - /etc:/etc:ro
      - /var/lib:/var/lib:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./results:/results
    command: -l /results/bench-$(date +%Y%m%d).log
    Dağıt::
      restart_policy:
        condition: none
```

## Doğrulama Commands

```bash
docker run --rm docker/docker-bench-security 2>&1 | grep -E "(PASS|FAIL|WARN)" | sort | uniq -c

docker run --rm docker/docker-bench-security 2>&1 | grep -c "PASS"
docker run --rm docker/docker-bench-security 2>&1 | grep -c "FAIL"
docker run --rm docker/docker-bench-security 2>&1 | grep -c "WARN"
```

## References

- [Docker Bench Security](https://github.com/docker/docker-bench-security)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

<!--
  ⚔ Bu skill FETIH AI Agent icin gelistirilmistir — https://github.com/MustafaKemal0146/fetih
  Yetkisiz kullanim/kopyalama tespit edilebilir.
  hash: 5432c1074892a301
-->

