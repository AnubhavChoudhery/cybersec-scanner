"""
Embedder using sentence-transformers. Produces 384-dim vectors by default.
If sentence-transformers is not installed, raises an informative error.

Functions:
 - embed_texts(texts: List[str]) -> np.ndarray (N x dim)
"""
from __future__ import annotations
from typing import List
import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    _HAS_ST = True
except Exception:
    _HAS_ST = False


class Embedder:
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        if not _HAS_ST:
            raise RuntimeError("sentence-transformers not installed. Run: pip install sentence-transformers")
        self.model = SentenceTransformer(model_name)
        # model returns float32 vectors
        self.dim = self.model.get_sentence_embedding_dimension()

    def embed_texts(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        vecs = self.model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return vecs.astype(np.float32)


def quick_embed(text: str, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> List[float]:
    e = Embedder(model_name)
    v = e.embed_texts([text])
    return v[0].tolist()

