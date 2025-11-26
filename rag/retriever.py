"""
Simple retriever that uses NetworkX knowledge graph to return findings matching a query.

Modes:
- graph: keyword matching on finding summary/snippet
- hybrid: (currently same as graph, placeholder for future vector integration)

Returns a list of contexts suitable for feeding into the LLM client.
"""
from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
from rag.knowledge_graph import KnowledgeGraph
import re


def _tokenize(q: str) -> List[str]:
    return [t.lower() for t in re.findall(r"\w+", q) if len(t) > 2]


class Retriever:
    def __init__(self, graph_path: Path | None = None):
        self.kg = KnowledgeGraph()
        if graph_path:
            self.kg.load(graph_path)

    def retrieve(self, query: str, k: int = 5, mode: str = "graph") -> List[Dict[str, Any]]:
        # For now mode is unused; we do simple keyword match over finding summaries and snippets
        toks = _tokenize(query)
        matches = []
        for node, data in self.kg.g.nodes(data=True):
            if data.get("label") != "Finding":
                continue
            text = (data.get("summary") or "") + " " + (data.get("snippet") or "")
            lo = text.lower()
            score = sum(1 for t in toks if t in lo)
            if score > 0:
                matches.append((score, node, data))

        # sort by score and severity
        def sev_rank(s):
            order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            return order.get(s.upper(), 1)

        matches.sort(key=lambda x: (-x[0], -sev_rank(x[2].get("severity", "INFO"))))
        results = []
        for score, node, data in matches[:k]:
            # attach id and basic fields expected by llm client
            fid = node.replace("finding:", "")
            results.append({
                "id": fid,
                "summary": data.get("summary"),
                "severity": data.get("severity"),
                "snippet": data.get("snippet"),
                "url": data.get("metadata", {}).get("url") or data.get("metadata", {}).get("endpoint")
            })
        return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--graph", default=None)
    p.add_argument("--query", required=True)
    args = p.parse_args()
    r = Retriever(Path(args.graph) if args.graph else None)
    res = r.retrieve(args.query, k=5)
    print(res)
