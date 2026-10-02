"""
Tool registry for the remediation agent.
All tools are READ-ONLY.  No shell, no network writes.
Arguments are validated against strict JSON schemas.
A call-count limit enforces the tool-call cap.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, field_validator

from vulnpilot.intel.loaders import EpssLoader, KevLoader

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "data"
_MAX_TOOL_CALLS = 5

# Allowed tool names (allowlist — no other tools can be called)
ALLOWED_TOOLS = {"lookup_cve", "search_knowledge", "check_fixed_version"}


# ---------------------------------------------------------------------------
# Argument schemas
# ---------------------------------------------------------------------------

class LookupCveArgs(BaseModel):
    cve_id: str

    @field_validator("cve_id")
    @classmethod
    def must_be_cve(cls, v: str) -> str:
        import re
        if not re.match(r"^CVE-\d{4}-\d+$", v.upper()):
            raise ValueError(f"Invalid CVE ID format: {v}")
        return v.upper()


class SearchKnowledgeArgs(BaseModel):
    query: str

    @field_validator("query")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("query must not be empty")
        return v[:256]  # prevent overly long queries


class CheckFixedVersionArgs(BaseModel):
    package: str
    current_version: str


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

class ToolRegistry:
    """
    Provides callable tools to the remediation agent.
    Enforces an allowlist and a per-session call-count limit.
    Logs every tool call.
    """

    def __init__(self, scan_vulns: list[Any] | None = None) -> None:
        self._kev = KevLoader(path=_DATA_DIR / "kev.json")
        self._epss = EpssLoader(path=_DATA_DIR / "epss.json")
        self._scan_vulns = scan_vulns or []
        self._call_count = 0

    def call(self, tool_name: str, raw_args: dict[str, Any]) -> str:
        """Dispatch a tool call.  Returns a string result for the agent."""
        if tool_name not in ALLOWED_TOOLS:
            return json.dumps({"error": f"Tool '{tool_name}' is not in the allowlist."})

        if self._call_count >= _MAX_TOOL_CALLS:
            return json.dumps({"error": "Tool call limit reached. Cannot call more tools."})

        self._call_count += 1
        logger.info("Tool call #%d: %s(%s)", self._call_count, tool_name, raw_args)

        try:
            if tool_name == "lookup_cve":
                args = LookupCveArgs(**raw_args)
                return self._lookup_cve(args.cve_id)
            elif tool_name == "search_knowledge":
                args2 = SearchKnowledgeArgs(**raw_args)
                return self._search_knowledge(args2.query)
            elif tool_name == "check_fixed_version":
                args3 = CheckFixedVersionArgs(**raw_args)
                return self._check_fixed_version(args3.package, args3.current_version)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Tool argument validation failed: {exc}"})

        return json.dumps({"error": "Unknown tool"})

    def _lookup_cve(self, cve_id: str) -> str:
        result: dict[str, Any] = {"cve_id": cve_id}
        result["in_kev"] = self._kev.is_kev(cve_id)
        epss = self._epss.get_score(cve_id)
        result["epss"] = epss
        # Look up from scan data
        for v in self._scan_vulns:
            if getattr(v, "id", None) == cve_id:
                result["package"] = getattr(v, "package", "unknown")
                result["severity"] = getattr(v, "severity", "unknown")
                result["fixed_version"] = getattr(v, "fixed_version", None)
                break
        return json.dumps(result)

    def _search_knowledge(self, query: str) -> str:
        """Search the local RAG knowledge base."""
        try:
            from vulnpilot.rag.knowledge_base import FakeEmbedder, KnowledgeBase
            kb = KnowledgeBase(embedder=FakeEmbedder())
            kb.build()
            results = kb.search(query, top_k=2)
            return json.dumps({"results": results})
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Knowledge base search failed: {exc}"})

    def _check_fixed_version(self, package: str, current_version: str) -> str:
        """Check if a fixed version exists for a package in the current scan."""
        for v in self._scan_vulns:
            if getattr(v, "package", "") == package:
                fixed = getattr(v, "fixed_version", None)
                return json.dumps({
                    "package": package,
                    "current_version": current_version,
                    "fixed_version": fixed,
                    "fix_available": fixed is not None,
                })
        return json.dumps({"package": package, "error": "Package not found in scan results."})

    @property
    def call_count(self) -> int:
        return self._call_count
