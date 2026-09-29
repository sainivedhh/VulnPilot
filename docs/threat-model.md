# VulnPilot Threat Model

## 1. Scope
This threat model covers the VulnPilot API, the CLI runner within GitHub Actions, and its deployment in Kubernetes.

## 2. Trust Boundaries
- **CI/CD Pipeline**: GitHub Actions environment running the CLI.
- **REST API**: External requests hitting the FastAPI service.
- **Kubernetes Cluster**: The boundary between deployed workloads and cluster networking.
- **External AI Provider**: Interaction between the VulnPilot API and external LLMs.

## 3. Threats and Mitigations

| Threat | Attack Scenario | Impact | Mitigation |
|--------|-----------------|--------|------------|
| **Malicious CI/CD input** | Attacker compromises a dependency to modify Trivy JSON output. | Bypass policy checks. | JSON Schema validation, strict Pydantic parsing. |
| **Prompt Injection** | Attacker sets a CVE description designed to manipulate the LLM triage. | AI recommends skipping a critical fix. | LLM fallback logic; Deterministic engine *always* acts as final source of truth. |
| **API Key Leakage** | OpenAI API key committed to source code. | Unauthorized LLM usage/billing. | Keys injected via environment variables and GitHub Secrets. `.gitignore` blocks `.env`. |
| **Privilege Escalation** | Vulnerability in FastAPI allows container breakout. | Cluster node compromise. | Container runs as non-root, read-only filesystem, drops all capabilities. Gatekeeper policy enforcement. |
