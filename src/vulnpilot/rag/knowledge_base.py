"""
RAG-based remediation assistant using FAISS + a pluggable embedding backend.
This is an optional feature; it requires `faiss-cpu` and `numpy`.
Run offline with the fake embedder (tests/eval/ or --use-fake-embedder flag).
"""
from __future__ import annotations

import abc
import hashlib
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path(__file__).parent.parent.parent.parent.parent / "docs" / "knowledge"


# ---------------------------------------------------------------------------
# Pluggable Embedder interface
# ---------------------------------------------------------------------------

class Embedder(abc.ABC):
    @abc.abstractmethod
    def embed(self, text: str) -> list[float]:
        ...


class FakeEmbedder(Embedder):
    """Deterministic fake embedder for offline tests.  Uses MD5 → floats."""

    def embed(self, text: str) -> list[float]:
        digest = hashlib.md5(text.encode()).digest()  # noqa: S324 – ok for tests
        return [b / 255.0 for b in digest]  # 16-dim vector


# ---------------------------------------------------------------------------
# Document chunker
# ---------------------------------------------------------------------------

def _chunk_text(text: str, chunk_size: int = 400, overlap: int = 80) -> list[str]:
    words = text.split()
    chunks: list[str] = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i:i + chunk_size])
        if chunk:
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """Loads markdown files from docs/knowledge/, chunks them, and indexes with FAISS."""

    def __init__(
        self,
        knowledge_dir: Optional[Path] = None,
        embedder: Optional[Embedder] = None,
    ) -> None:
        self._dir = knowledge_dir or KNOWLEDGE_DIR
        self._embedder = embedder or FakeEmbedder()
        self._chunks: list[str] = []
        self._sources: list[str] = []
        self._index: object = None
        self._built = False

    def build(self) -> None:
        """Load, chunk, embed, and index all knowledge files."""
        try:
            import faiss  # type: ignore[import-untyped]
            import numpy as np  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("faiss-cpu or numpy not installed; KB disabled. "
                           "Install with: pip install faiss-cpu numpy")
            return

        chunks: list[str] = []
        sources: list[str] = []

        for md_file in sorted(self._dir.glob("*.md")):
            text = md_file.read_text(encoding="utf-8")
            for chunk in _chunk_text(text):
                chunks.append(chunk)
                sources.append(md_file.name)

        if not chunks:
            logger.warning("No knowledge chunks found in %s", self._dir)
            return

        vectors = np.array([self._embedder.embed(c) for c in chunks], dtype="float32")
        dim = vectors.shape[1]
        index = faiss.IndexFlatL2(dim)
        index.add(vectors)  # type: ignore[call-arg]

        self._chunks = chunks
        self._sources = sources
        self._index = index
        self._built = True
        logger.info("Knowledge base built: %d chunks from %s", len(chunks), self._dir)

    def search(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        """Return top-k relevant chunks with their source filenames."""
        if not self._built:
            return [{"source": "kb_disabled", "text": "Knowledge base not available."}]

        try:
            import faiss  # type: ignore[import-untyped]
            import numpy as np  # type: ignore[import-untyped]
        except ImportError:
            return []

        vec = np.array([self._embedder.embed(query)], dtype="float32")
        distances, indices = self._index.search(vec, top_k)  # type: ignore[call-arg]
        results = []
        for idx in indices[0]:
            if 0 <= idx < len(self._chunks):
                results.append({
                    "source": self._sources[idx],
                    "text": self._chunks[idx],
                })
        return results
