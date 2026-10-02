"""VulnPilot RAG Knowledge Base — Container and base image hardening."""

# Remediation: Container and Base Image Hardening
## Class
Insecure Configuration (CWE-16), Exposed Docker Socket, Privileged Container

## Description
Misconfigured containers can allow attackers to escape to the host, access other
containers, or perform privilege escalation.

## Common Issues
- Running containers as root (UID 0)
- `privileged: true` in Kubernetes pods
- Missing `readOnlyRootFilesystem`
- Capabilities not dropped
- Outdated base images with known CVEs

## Remediation Steps

### Base Image
1. **Use minimal base images**: `distroless`, `scratch`, `alpine`, or `-slim` variants.
2. **Pin image digests** in production: `FROM python:3.12-slim@sha256:...`
3. **Regularly update** base images and rebuild.

### Kubernetes Pod Security
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

### Dockerfile Hardening
```dockerfile
FROM python:3.12-slim
RUN useradd --create-home --shell /bin/sh appuser
WORKDIR /app
COPY --chown=appuser:appuser . .
USER appuser
```

## References
- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
- NSA/CISA Kubernetes Hardening Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
