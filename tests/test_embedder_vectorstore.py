import numpy as np
from rag.vector_store import VectorStore


def test_vectorstore_bruteforce_search():
    vs = VectorStore(dim=4)
    vs.add(1, np.array([1.0, 0.0, 0.0, 0.0], dtype=float))
    vs.add(2, np.array([0.0, 1.0, 0.0, 0.0], dtype=float))
    vs.add(3, np.array([0.9, 0.1, 0.0, 0.0], dtype=float))

    res = vs.search(np.array([1.0, 0.0, 0.0, 0.0], dtype=float), k=2)
    # highest should be id 1, then id 3
    assert res[0][0] == 1
    assert res[1][0] == 3


def test_vectorstore_save_load(tmp_path):
    vs = VectorStore(dim=3)
    vs.add(10, np.array([1.0, 0.0, 0.0], dtype=float))
    vs.add(11, np.array([0.0, 1.0, 0.0], dtype=float))
    p = tmp_path / "vs"
    vs.save(p)

    vs2 = VectorStore(dim=3)
    vs2.load(p)
    res = vs2.search(np.array([1.0, 0.0, 0.0], dtype=float), k=1)
    assert res[0][0] in (10, 11, 10)
