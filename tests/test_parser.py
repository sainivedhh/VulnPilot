import os
from pathlib import Path
from vulnpilot.scanners.trivy import TrivyParser

def test_trivy_parser():
    fixture_path = Path(__file__).parent / "fixtures" / "trivy_sample.json"
    parser = TrivyParser()
    vulns = parser.parse_file(str(fixture_path))
    
    assert len(vulns) == 1
    v = vulns[0]
    
    assert v.id == "CVE-2019-14697"
    assert v.package == "musl"
    assert v.installed_version == "1.1.22-r2"
    assert v.fixed_version == "1.1.22-r3"
    assert v.severity == "HIGH"
    assert v.cvss == 9.8
    assert "musl libc" in v.title
