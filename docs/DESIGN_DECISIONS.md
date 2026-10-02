# Design Decisions (ADRs)

## ADR-1: Deterministic core + advisory LLM

**Decision**: The risk score, policy decision, and pipeline gate are always
determined by the deterministic `RiskEngine` and `PolicyEvaluator`.
The LLM is purely advisory — it provides rationale and suggested fixes,
but cannot change a BLOCK decision to PASS.

**Rationale**:
- Deterministic systems are auditable, reproducible, and testable.
- LLMs can hallucinate, be manipulated by prompt injection, or be unavailable.
- Security decisions must be explainable to compliance auditors.
- The `FallbackProvider` ensures the pipeline always terminates even if the LLM is down.

**Rejected alternative**: Letting the LLM override policy decisions based on context.
This was rejected because it creates an unverifiable trust chain.

---

## ADR-2: Pydantic for all data models

**Decision**: Every data structure that crosses a trust boundary
(parser output, risk scores, API requests/responses, LLM output) is
validated by a Pydantic model.

**Rationale**:
- Pydantic provides automatic type coercion, validation, and clear error messages.
- Validation at every boundary ensures that malformed or injected data is caught early.
- Pydantic v2 is significantly faster than v1 (Rust core via pydantic-core).

**Consequences**: Tests must supply all required fields; optional fields must
be explicitly typed as `Optional[X]`.

---

## ADR-3: YAML for security policies

**Decision**: Pipeline security gates are defined in declarative YAML
(`policies/pipeline-policy.yaml`) rather than Python code.

**Rationale**:
- YAML policies can be reviewed and changed by security engineers without Python knowledge.
- Version-controlled YAML provides an audit trail of policy changes.
- Policy files can be mounted as Kubernetes ConfigMaps, decoupling them from the container image.

**Rejected alternative**: Hardcoded severity thresholds in Python.
This was rejected because it forces a code change and new deployment for every policy update.

---

## ADR-4: Offline-first intelligence (KEV / EPSS)

**Decision**: KEV and EPSS data are loaded from locally cached JSON files,
not fetched at runtime during scans.

**Rationale**:
- Network calls at scan time add latency and introduce availability risk.
- CI pipelines must not depend on external services for correctness.
- `vulnpilot update-intel` is an explicit refresh step that can be cached in CI.

---

## ADR-5: Provider abstraction for LLM backends

**Decision**: LLM integration uses an abstract `TriageProvider` base class
with `FallbackProvider`, `MockProvider`, and `OpenAIProvider` implementations.

**Rationale**:
- The mock provider enables fully offline test runs with zero network access.
- The abstraction makes it trivial to add Azure OpenAI, Anthropic, or Gemini backends.
- The circuit breaker pattern prevents cascading failures when the LLM is unavailable.
