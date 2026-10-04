from __future__ import annotations

import json
from typing import Any

from .models import Vulnerability


class TrivyParser:
    def parse_file(self, file_path: str) -> list[Vulnerability]:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return self.parse_dict(data)

    def parse_dict(self, data: dict[str, Any]) -> list[Vulnerability]:
        vulnerabilities = []
        results = data.get('Results', [])
        for result in results:
            vulns = result.get('Vulnerabilities', [])
            for v in vulns:
                cvss_score = None
                cvss_data = v.get('CVSS', {})
                # Try to get the NVD V3 score first
                if 'nvd' in cvss_data and 'V3Score' in cvss_data['nvd']:
                    cvss_score = cvss_data['nvd']['V3Score']
                elif 'nvd' in cvss_data and 'V2Score' in cvss_data['nvd']:
                    cvss_score = cvss_data['nvd']['V2Score']
                
                vuln = Vulnerability(
                    id=v.get('VulnerabilityID', 'UNKNOWN'),
                    package=v.get('PkgName', 'UNKNOWN'),
                    installed_version=v.get('InstalledVersion', 'UNKNOWN'),
                    fixed_version=v.get('FixedVersion'),
                    severity=v.get('Severity', 'UNKNOWN'),
                    cvss=cvss_score,
                    title=v.get('Title'),
                    description=v.get('Description')
                )
                vulnerabilities.append(vuln)
        return vulnerabilities
