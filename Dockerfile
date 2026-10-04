# Multi-stage hardened Dockerfile
# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt \
    && pip install --no-cache-dir --prefix=/install -e . --no-deps

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime — minimal surface area
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="VulnPilot" \
      org.opencontainers.image.description="AI-Assisted DevSecOps Pipeline" \
      org.opencontainers.image.source="https://github.com/sainivedhh/VulnPilot"

# Create a non-root user (uid/gid 10001 — not a system account)
RUN useradd --uid 10001 --gid 0 --no-create-home --shell /bin/false vulnpilot

WORKDIR /app

# Copy installed packages from build stage
COPY --from=builder /install /usr/local

# Copy application source (no .git, no tests)
COPY --chown=10001:0 src/ ./src/
COPY --chown=10001:0 policies/ ./policies/
COPY --chown=10001:0 data/ ./data/

# Drop to non-root
USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["python", "-m", "vulnpilot.main", "serve", "--host", "0.0.0.0"]
