import typer
import uvicorn
from typing import Optional
from pathlib import Path
from fastapi import FastAPI
from vulnpilot.scanners.trivy import TrivyParser
from vulnpilot.triage.risk_engine import RiskEngine, WorkloadContext
from vulnpilot.policy.evaluator import PolicyEvaluator
from vulnpilot.api.routes import router

app = typer.Typer(help="VulnPilot - AI-Assisted DevSecOps Pipeline")
api_app = FastAPI(title="VulnPilot API", description="AI-Assisted DevSecOps Pipeline API")
api_app.include_router(router)

@app.command()
def scan(file_path: str, policy_file: str = "policies/pipeline-policy.yaml"):
    """
    Parse a Trivy JSON report, apply risk scoring, and evaluate against policies.
    """
    path = Path(file_path)
    if not path.exists():
        typer.echo(f"Error: File '{file_path}' does not exist.")
        raise typer.Exit(code=1)
    
    parser = TrivyParser()
    engine = RiskEngine()
    context = WorkloadContext(internet_exposed=True, runtime_environment="production")
    
    try:
        vulns = parser.parse_file(str(path))
        typer.echo(f"[*] Parsed {len(vulns)} vulnerabilities from {file_path}")
        
        findings = []
        for v in vulns:
            risk = engine.evaluate(v, context)
            findings.append((v, risk))
            typer.echo(f"  - {v.id} [{v.severity}] -> Risk Score: {risk.score} ({risk.category})")

        # Policy Evaluation
        if Path(policy_file).exists():
            evaluator = PolicyEvaluator(policy_file)
            result = evaluator.evaluate(findings)
            typer.echo(f"\n[*] Policy Decision: {result.decision}")
            for v in result.violations:
                typer.echo(f"  ! {v}")
            
            if result.decision == "BLOCK":
                raise typer.Exit(code=1)
        else:
            typer.echo(f"[*] No policy file found at {policy_file}. Skipping enforcement.")

    except Exception as e:
        typer.echo(f"Failed to process file: {e}")
        raise typer.Exit(code=1)

@app.command()
def serve(host: str = "0.0.0.0", port: int = 8000):
    """
    Start the FastAPI REST service.
    """
    typer.echo(f"Starting VulnPilot API on {host}:{port}...")
    uvicorn.run(api_app, host=host, port=port)

if __name__ == "__main__":
    app()
