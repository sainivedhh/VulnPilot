"""VulnPilot RAG Knowledge Base — Deserialization remediation guidance."""

# Remediation: Insecure Deserialization
## Class
Insecure Deserialization (CWE-502)

## Description
Deserializing untrusted data can lead to remote code execution, authentication bypass,
or denial of service. This is one of the OWASP Top 10 critical risks.

## Common Packages / Scenarios
- Python: `pickle`, `yaml.load()` (without Loader), `marshal`
- Java: `ObjectInputStream`, `XStream`, `Jackson` with polymorphism
- PHP: `unserialize()`

## Remediation Steps
1. **Never deserialize data from untrusted sources** using `pickle`, `yaml.load` (unsafe), or `marshal`.
2. **Use safe alternatives**: `json`, `yaml.safe_load()`, or protobuf.
3. **Integrity checking**: sign serialized objects with HMAC before deserializing.
4. **Run deserialization in a sandboxed environment** with minimal privileges.
5. **Monitor and alert** on deserialization exceptions, which often indicate attack attempts.

## Example Fix (Python)
```python
import yaml

# VULNERABLE
data = yaml.load(user_input)

# SAFE
data = yaml.safe_load(user_input)
```

## Base Image Upgrade Guidance
If the vulnerability is in a base image dependency, upgrade the base image:
```dockerfile
# BEFORE
FROM python:3.9-slim
# AFTER (check for latest patched version)
FROM python:3.12-slim
```

## References
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
