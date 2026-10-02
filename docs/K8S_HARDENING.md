# K8s Hardening Guide

## Control Mapping

| Control | Manifest / Config | Attack Mitigated |
|---------|------------------|-----------------|
| `runAsNonRoot: true` | `kubernetes/deployment.yaml:L18` | Container escape via UID 0 |
| `runAsUser: 10001` | `kubernetes/deployment.yaml:L19` | Root privilege inside container |
| `readOnlyRootFilesystem: true` | `kubernetes/deployment.yaml:L28` | Malware persistence via disk writes |
| `allowPrivilegeEscalation: false` | `kubernetes/deployment.yaml:L27` | SUID/SGID escalation |
| `capabilities.drop: ALL` | `kubernetes/deployment.yaml:L29-31` | Linux capability abuse (e.g., NET_RAW) |
| `seccompProfile: RuntimeDefault` | `kubernetes/deployment.yaml:L21-22` | Syscall abuse (e.g., ptrace) |
| `automountServiceAccountToken: false` | `kubernetes/deployment.yaml:L14` | Token theft → K8s API abuse |
| Resource limits | `kubernetes/deployment.yaml:L32-38` | CPU/memory denial of service |
| `NetworkPolicy` (default deny) | `kubernetes/deployment.yaml:L59-79` | Lateral movement between pods |
| OPA Gatekeeper admission | `policies/gatekeeper/constraint-template.yaml` | Privileged pod deployment |
| OPA Rego privileged check | `policies/rego/k8s_security.rego` | Policy drift detection |
| Falco: package manager rule | `falco/custom-rules.yaml:L1-17` | Living-off-the-land attacks |
| Falco: shell spawn rule | `falco/custom-rules.yaml:L19-35` | Interactive shell in container |
| Falco: write to /etc rule | `falco/custom-rules.yaml:L37-53` | Persistence via config tampering |

## Pod Security Admission

Apply the `restricted` profile to the production namespace:
```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

## Testing Falco Rules

Falco rules can be validated using `falco -r custom-rules.yaml -M 5 -e /dev/null` for syntax,
and tested against recorded event streams (`.scap` files) using `falco-tester`.

**Example event fixture for shell spawn:**
```json
{
  "evt.type": "execve",
  "proc.name": "bash",
  "proc.pname": "python3",
  "container.id": "abc123",
  "container.name": "api",
  "container.image.repository": "vulnpilot"
}
```
This event should trigger the "Shell spawned in container" rule at WARNING priority.
