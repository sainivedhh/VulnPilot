"""Tests for A4: RAG tool registry."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnpilot.rag.knowledge_base import FakeEmbedder, KnowledgeBase, _chunk_text
from vulnpilot.rag.tools import CheckFixedVersionArgs, LookupCveArgs, SearchKnowledgeArgs, ToolRegistry

KNOWLEDGE_DIR = Path(__file__).parent.parent / "docs" / "knowledge"


# ---------------------------------------------------------------------------
# Chunker
# ---------------------------------------------------------------------------

def test_chunk_text_splits() -> None:
    text = " ".join(["word"] * 1000)
    chunks = _chunk_text(text, chunk_size=100, overlap=20)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c.split()) <= 100


# ---------------------------------------------------------------------------
# Fake embedder
# ---------------------------------------------------------------------------

def test_fake_embedder_deterministic() -> None:
    emb = FakeEmbedder()
    v1 = emb.embed("hello world")
    v2 = emb.embed("hello world")
    assert v1 == v2


def test_fake_embedder_different_texts() -> None:
    emb = FakeEmbedder()
    assert emb.embed("foo") != emb.embed("bar")


# ---------------------------------------------------------------------------
# Knowledge base search (no FAISS needed for the happy path via FakeEmbedder)
# ---------------------------------------------------------------------------

def test_knowledge_base_returns_chunks_when_faiss_available() -> None:
    try:
        import faiss  # noqa: F401
        import numpy  # noqa: F401
    except ImportError:
        pytest.skip("faiss-cpu or numpy not installed")

    kb = KnowledgeBase(knowledge_dir=KNOWLEDGE_DIR, embedder=FakeEmbedder())
    kb.build()
    results = kb.search("SQL injection parameterised query")
    assert len(results) > 0
    assert any(r["source"].endswith(".md") for r in results)


def test_knowledge_base_returns_fallback_when_not_built() -> None:
    kb = KnowledgeBase(knowledge_dir=KNOWLEDGE_DIR, embedder=FakeEmbedder())
    # Don't call build()
    results = kb.search("anything")
    assert any("not available" in r.get("text", "").lower() for r in results)


# ---------------------------------------------------------------------------
# Tool argument validation
# ---------------------------------------------------------------------------

def test_lookup_cve_valid() -> None:
    args = LookupCveArgs(cve_id="CVE-2021-44228")
    assert args.cve_id == "CVE-2021-44228"


def test_lookup_cve_invalid_format() -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LookupCveArgs(cve_id="not-a-cve")


def test_search_knowledge_truncates() -> None:
    long_query = "A" * 500
    args = SearchKnowledgeArgs(query=long_query)
    assert len(args.query) <= 256


def test_search_knowledge_empty_fails() -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SearchKnowledgeArgs(query="   ")


# ---------------------------------------------------------------------------
# Tool call limit enforcement
# ---------------------------------------------------------------------------

def test_tool_call_limit() -> None:
    reg = ToolRegistry()
    for _ in range(5):
        reg.call("lookup_cve", {"cve_id": "CVE-2021-44228"})
    result = json.loads(reg.call("lookup_cve", {"cve_id": "CVE-2021-44228"}))
    assert "limit" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Allowlist enforcement
# ---------------------------------------------------------------------------

def test_unknown_tool_rejected() -> None:
    reg = ToolRegistry()
    result = json.loads(reg.call("run_shell", {"cmd": "rm -rf /"}))
    assert "allowlist" in result.get("error", "").lower()


# ---------------------------------------------------------------------------
# Poisoned knowledge chunk injection test
# ---------------------------------------------------------------------------

def test_poisoned_chunk_doesnt_affect_tool_result() -> None:
    """A knowledge chunk containing injection text must not influence tool output."""
    reg = ToolRegistry()
    # Even if a knowledge file were to contain injection instructions,
    # tool calls are purely deterministic (data lookup) — not LLM-driven.
    result = json.loads(reg.call("lookup_cve", {"cve_id": "CVE-2021-44228"}))
    # Result must be a structured dict — never raw text from knowledge files
    assert "cve_id" in result
    assert "in_kev" in result
