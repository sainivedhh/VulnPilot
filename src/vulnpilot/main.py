"""VulnPilot CLI & FastAPI entry point."""
from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import typer
import uvicorn
from fastapi import FastAPI

from vulnpilot.api.routes import router
from vulnpilot.intel.updater import update_epss, update_kev
from vulnpilot.policy.evaluator import PolicyEvaluator
from vulnpilot.scanners.trivy import TrivyParser
from vulnpilot.triage.risk_engine import RiskEngine, ScoringWeights, WorkloadContext

app = typer.Typer(help="VulnPilot - AI-Assisted DevSecOps Pipeline")
api_app = FastAPI(title="VulnPilot API",
                  description="AI-Assisted DevSecOps Pipeline API")
api_app.include_router(router)


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    markdown = "markdown"
    sarif = "sarif"


def _build_sarif(findings: list) -> dict:  # type: ignore[type-arg]
    runs = [{
        "tool": {"driver": {"name": "VulnPilot", "version": "0.2.0"}},
        "results": [
            {
                "ruleId": v.id,
                "message": {"text": f"{v.id} in {v.package} – Risk {risk.score}/100 ({risk.category})"},
                "level": "error" if risk.score >= 70 else "warning",
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "Dockerfile"},
                }}],
                "properties": {
                    "score": risk.score,
                    "explanation": [f.name for f in risk.explanation.factors],
                },
            }
            for v, risk in findings
        ],
    }]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs}


@app.command()
def scan(
    file_path: str,
    policy_file: str = "policies/pipeline-policy.yaml",
    scoring_config: str | None = None,
    format: OutputFormat = OutputFormat.table,
) -> None:
    """Parse a Trivy JSON report, apply risk scoring, and evaluate against policies."""
    path = Path(file_path)
    if not path.exists():
        typer.echo(f"Error: File '{file_path}' does not exist.")
        raise typer.Exit(code=1)

    # Build engine
    if scoring_config and Path(scoring_config).exists():
        weights = ScoringWeights.from_yaml(Path(scoring_config))
        engine = RiskEngine(weights=weights)
    else:
        engine = RiskEngine()

    context = WorkloadContext(internet_exposed=True, runtime_environment="production")
    parser = TrivyParser()

    try:
        vulns = parser.parse_file(str(path))
    except Exception as exc:
        typer.echo(f"Failed to parse file: {exc}")
        raise typer.Exit(code=1) from exc

    findings = [(v, engine.evaluate(v, context)) for v in vulns]

    # ---- Output ----
    if format == OutputFormat.json:
        output = [
            {
                "id": v.id,
                "package": v.package,
                "severity": v.severity,
                "score": risk.score,
                "category": risk.category,
                "explanation": [{"name": f.name, "points": f.points, "detail": f.detail}
                                 for f in risk.explanation.factors],
            }
            for v, risk in findings
        ]
        typer.echo(json.dumps(output, indent=2))

    elif format == OutputFormat.markdown:
        typer.echo("\n## VulnPilot Scan Results\n\n| CVE | Package | Severity | Score | Category |")
        typer.echo("|-----|---------|----------|-------|----------|")
        for v, risk in findings:
            typer.echo(f"| {v.id} | {v.package} | {v.severity} | {risk.score} | {risk.category} |")

    elif format == OutputFormat.sarif:
        typer.echo(json.dumps(_build_sarif(findings), indent=2))

    else:  # table (default)
        typer.echo(f"\n[*] Parsed {len(vulns)} vulnerabilities from {file_path}")
        for v, risk in findings:
            typer.echo(f"  - {v.id} [{v.severity}] → Risk Score: {risk.score}/100 ({risk.category})")
            for factor in risk.explanation.factors:
                typer.echo(f"      {factor.name:20s} +{factor.points:3d}  {factor.detail}")

    # ---- Policy ----
    if Path(policy_file).exists():
        evaluator = PolicyEvaluator(policy_file)
        result = evaluator.evaluate(findings)
        typer.echo(f"\n[*] Policy Decision: {result.decision}")
        for violation in result.violations:
            typer.echo(f"  ! {violation}")
        if result.decision == "BLOCK":
            raise typer.Exit(code=1)
    else:
        typer.echo(f"[*] No policy file at {policy_file}. Skipping enforcement.")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the FastAPI REST service."""
    typer.echo(f"Starting VulnPilot API on {host}:{port}...")
    uvicorn.run(api_app, host=host, port=port)


@app.command(name="update-intel")
def update_intel(
    timeout: int = typer.Option(30, help="HTTP timeout in seconds"),
) -> None:
    """Refresh KEV and EPSS intel from upstream sources (requires internet)."""
    typer.echo("[*] Updating CISA KEV catalog...")
    ok_kev = update_kev(timeout=timeout)
    typer.echo("[*] Updating EPSS scores...")
    ok_epss = update_epss(timeout=timeout)
    if ok_kev and ok_epss:
        typer.echo("[✓] Intel refresh complete.")
    else:
        typer.echo("[!] One or more updates failed. Check logs.", err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
