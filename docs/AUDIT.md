# VulnPilot Audit Report

## 1. Feature Claims vs. Reality

| Claim | Status | File Paths | Notes |
|-------|--------|------------|-------|
| Trivy JSON parsing into normalized, typed Pydantic models | **IMPLEMENTED** | `src/vulnpilot/scanners/parser.py`, `src/vulnpilot/scanners/trivy.py`, `src/vulnpilot/scanners/models.py` | Full implementation with Pydantic models. |
| Deterministic contextual risk score (0-100) from CVSS plus workload context | **IMPLEMENTED** | `src/vulnpilot/triage/risk_engine.py` | Correctly processes CVSS and modifies scores based on internet exposure and production environment. |
| Policy engine enforcing security gates from declarative YAML | **IMPLEMENTED** | `src/vulnpilot/policy/evaluator.py`, `policies/pipeline-policy.yaml` | Successfully evaluates risk scores against YAML definitions. |
| AI triage layer with deterministic fallback | **PARTIAL** | `src/vulnpilot/triage/ai_analyzer.py` | Deterministic fallback is implemented, but the actual LLM API call is stubbed out. No real LLM integration exists yet. |
| FastAPI REST service and Typer CLI | **IMPLEMENTED** | `src/vulnpilot/main.py`, `src/vulnpilot/api/routes.py` | Both CLI commands and the FastAPI app setup are present. |
| Hardened Kubernetes manifests (non-root, dropped capabilities, read-only root filesystem) | **IMPLEMENTED** | `kubernetes/deployment.yaml` | `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and all capabilities dropped. |
| OPA Gatekeeper policy blocking privileged pods | **IMPLEMENTED** | `policies/gatekeeper/constraint-template.yaml` | Present in the policies folder. |
| Falco rule detecting package-manager execution | **IMPLEMENTED** | `falco/custom-rules.yaml` | Detects `apt`, `apk`, `yum`, etc., in containers. |
| GitHub Actions running test, build, scan, policy-enforce | **IMPLEMENTED** | `.github/workflows/ci.yml` | Workflow includes all stated steps. |
| STRIDE threat model document | **IMPLEMENTED** | `docs/threat-model.md` | Contains a basic STRIDE model and trust boundaries. |
| Pytest coverage of parsing, risk scoring and policy enforcement | **IMPLEMENTED** | `tests/` | Tests for these modules are present and passing. |

## 2. Test Suite Results
- **Pass/Fail**: 8 tests passed, 0 failures.
- **Coverage**: Total coverage is **48%**.
  - `src/vulnpilot/scanners/trivy.py`: 91%
  - `src/vulnpilot/triage/risk_engine.py`: 90%
  - `src/vulnpilot/policy/evaluator.py`: 93%
  - `src/vulnpilot/triage/ai_analyzer.py`: 0%
  - `src/vulnpilot/main.py`: 0%
  - `src/vulnpilot/api/routes.py`: 0%

## 3. README Contradictions
The `README.md` explicitly states that only "Phase 1" is complete. However, the codebase has already progressed much further.
**Contradictions:**
- **Section 3 (Architecture)**: States *"Future phases will introduce the Risk Engine, Policy Engine, AI-Assisted Triage, and Kubernetes deployment components."* -> These components already exist in the codebase.
- **Section 4 (Features)**: Lists Deterministic risk scoring, OPA Gatekeeper policies, Falco runtime monitoring, and AI enrichment as *"Future"* features. -> These are already partially or fully implemented.

## 4. Prioritized Gap Report & Recommended Order of Work

### What Exists
- Robust parsing, risk scoring, and policy evaluation with solid test coverage.
- Basic K8s, Falco, and Gatekeeper configurations.
- CLI scaffolding and a basic FastAPI service.
- Functional GitHub Actions pipeline.

### What is Missing
- Real LLM integration in `ai_analyzer.py`.
- Tests for `ai_analyzer.py`, `main.py`, and `api/routes.py` (which currently have 0% coverage).
- Accurate documentation in `README.md` reflecting the actual state of the project.

### Bugs / Security Issues Found
- Missing real logic for the AI Triage layer (returns fallback directly).
- Test coverage for the API and AI layers is non-existent.

### Recommended Order of Work
1. **A1: Make the repo honest and solid**: Fix the `README.md` to reflect the actual features, add type hints, `ruff`, `mypy`, and improve test coverage to at least 85% overall.
2. **A2: Smarter, explainable risk engine**: Enhance the deterministic risk engine with KEV/EPSS data.
3. **A3: Harden and evaluate the AI triage layer**: Implement the actual LLM API calls with structured Pydantic outputs and security guardrails.
4. **A4: Agentic and RAG remediation assistant**: Add the local RAG knowledge base and tool calling.
5. **A5: Policy-as-code, Kubernetes and runtime security**: Expand policies and write automated tests for them.
6. **A6: CI/CD and software supply chain**: Upgrade GitHub actions with SBOM generation, signing, and CodeQL.
7. **A7: Infrastructure-as-Code and cloud**: Set up Terraform for automated deployment.
8. **A8: Documentation and threat model**: Finalize and expand the threat model and project documentation.
