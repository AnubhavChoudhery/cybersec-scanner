"""
Vector store abstraction with hnswlib backend when available.
Falls back to a simple in-memory numpy brute-force index when hnswlib is not installed
so development and tests can run on Windows without C++ build tools.

API:
 - add(item_id: int, vector: np.ndarray)
 - search(query_vector, k=10) -> list of (item_id, score)
 - save(path)
 - load(path)
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import List, Tuple
import numpy as np

try:
    import hnswlib
    _HAS_HNSW = True
except Exception:
    _HAS_HNSW = False


class VectorStore:
    def __init__(self, dim: int = 384):
        self.dim = dim
        self._ids: List[int] = []
        self._vecs: List[np.ndarray] = []
        self._index = None
        if _HAS_HNSW:
            # create hnsw index placeholder; initialize when adding
            self._index = hnswlib.Index(space='cosine', dim=self.dim)
            self._index_inited = False

    def add(self, item_id: int, vector: np.ndarray):
        vec = np.asarray(vector, dtype=np.float32)
        if vec.shape != (self.dim,):
            raise ValueError(f"Vector must have shape ({self.dim},), got {vec.shape}")

        self._ids.append(int(item_id))
        self._vecs.append(vec)

        if _HAS_HNSW:
            if not self._index_inited:
                # initialize with a guess for max elements
                self._index.init_index(max_elements=10000, ef_construction=200, M=16)
                self._index_inited = True
            self._index.add_items(vec.reshape(1, -1), [int(item_id)])

    def _search_bruteforce(self, qvec: np.ndarray, k: int = 10) -> List[Tuple[int, float]]:
        if not self._vecs:
            return []
        mats = np.vstack(self._vecs)  # Nxd
        q = qvec.astype(np.float32)
        # cosine similarity = dot / (||a||*||b||) ; we return similarity
        dot = mats.dot(q)
        norms = np.linalg.norm(mats, axis=1) * (np.linalg.norm(q) + 1e-12)
        sims = dot / norms
        idx = np.argsort(-sims)[:k]
        return [(int(self._ids[i]), float(sims[i])) for i in idx]

    def search(self, query_vector: np.ndarray, k: int = 10) -> List[Tuple[int, float]]:
        q = np.asarray(query_vector, dtype=np.float32)
        if _HAS_HNSW and self._index_inited:
            labels, distances = self._index.knn_query(q.reshape(1, -1), k=k)
            # hnswlib returns distances in cosine (1 - cosine) when space='cosine'
            results = []
            for lab, dist in zip(labels[0], distances[0]):
                if lab == -1:
                    continue
                score = 1.0 - float(dist)
                results.append((int(lab), score))
            return results
        else:
            return self._search_bruteforce(q, k=k)

    def save(self, path: str | Path):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # save vectors as .npz and ids as .npy
        np.savez_compressed(p.with_suffix('.npz'), vecs=np.vstack(self._vecs) if self._vecs else np.zeros((0, self.dim), dtype=np.float32))
        np.save(p.with_suffix('.ids.npy'), np.array(self._ids, dtype=np.int64))
        # if hnsw present and index inited, save index too
        if _HAS_HNSW and self._index_inited:
            try:
                self._index.save_index(str(p.with_suffix('.hnsw')))
            except Exception:
                pass

    def load(self, path: str | Path):
        p = Path(path)
        arr = np.load(p.with_suffix('.npz'))
        vecs = arr['vecs']
        ids = np.load(p.with_suffix('.ids.npy'))
        self._vecs = [vecs[i].astype(np.float32) for i in range(len(ids))]
        self._ids = [int(x) for x in ids.tolist()]
        if _HAS_HNSW:
            try:
                self._index.load_index(str(p.with_suffix('.hnsw')))
                self._index_inited = True
            except Exception:
                self._index_inited = False

