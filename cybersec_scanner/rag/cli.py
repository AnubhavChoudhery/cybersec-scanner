"""
CLI to query the local RAG pipeline: build graph (if needed), retrieve contexts, and call the local LLM (Ollama).
"""
from __future__ import annotations
from pathlib import Path
from .retriever import Retriever
from .llm_client import generate_answer


def query_graph_and_llm(query: str, graph_path: str | None = None, model: str = "gemma3:1b", k: int = 6):
    graph_file = Path(graph_path) if graph_path else (Path(__file__).parent / "graph.gpickle")
    r = Retriever(graph_file if graph_file.exists() else None)
    contexts = r.retrieve(query, k=k)
    result = generate_answer(query, contexts, model=model)
    return result


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--query", required=True)
    p.add_argument("--graph", default=None)
    p.add_argument("--model", default="gemma3:1b")
    args = p.parse_args()
    res = query_graph_and_llm(args.query, args.graph, args.model)
    print("--- Answer ---\n")
    print(res.get("text"))
    print("\n--- Raw ---\n")
    print(res.get("raw"))
