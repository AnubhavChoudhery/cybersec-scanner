"""
Retriever that uses knowledge graph and/or vector search.

Modes:
- graph: keyword matching on finding summary/snippet
- vector: semantic search using embeddings (requires embedder + vector_store)
- hybrid: combines both graph and vector search with ranking

Returns a list of contexts suitable for feeding into the LLM client.
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional
from pathlib import Path
from rag.knowledge_graph import KnowledgeGraph
import re


def _tokenize(q: str) -> List[str]:
    return [t.lower() for t in re.findall(r"\w+", q) if len(t) > 2]


class Retriever:
    def __init__(
        self, 
        graph_path: Path | None = None,
        embedder = None,
        vector_store = None
    ):
        """
        Initialize retriever with graph and optional vector components.
        
        Args:
            graph_path: Path to saved knowledge graph
            embedder: Embedder instance (optional, for vector search)
            vector_store: VectorStore instance (optional, for vector search)
        """
        self.kg = KnowledgeGraph()
        if graph_path:
            self.kg.load(graph_path)
        
        self.embedder = embedder
        self.vector_store = vector_store

    def retrieve(self, query: str, k: int = 5, mode: str = "graph") -> List[Dict[str, Any]]:
        """
        Retrieve relevant findings for query.
        
        Args:
            query: User query string
            k: Number of results to return
            mode: Retrieval mode ('graph', 'vector', or 'hybrid')
            
        Returns:
            List of finding dicts with id, summary, severity, snippet, url
        """
        if mode == "vector":
            return self._vector_retrieve(query, k)
        elif mode == "hybrid":
            return self._hybrid_retrieve(query, k)
        else:  # mode == "graph"
            return self._graph_retrieve(query, k)
            return self._graph_retrieve(query, k)
    
    def _graph_retrieve(self, query: str, k: int) -> List[Dict[str, Any]]:
        """Graph-based keyword search."""
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
    
    def _vector_retrieve(self, query: str, k: int) -> List[Dict[str, Any]]:
        """Vector-based semantic search."""
        if not self.embedder or not self.vector_store:
            raise RuntimeError(
                "Vector search requires embedder and vector_store. "
                "Initialize Retriever with these components or use mode='graph'."
            )
        
        # Embed query
        query_vector = self.embedder.embed_texts([query])[0]
        
        # Search vector store
        results = self.vector_store.search(query_vector, k=k * 2)  # Get more candidates
        
        # Map back to findings in graph
        findings = []
        for item_id, distance in results[:k]:
            # item_id should be finding node id
            node_data = self.kg.g.nodes.get(item_id)
            if node_data and node_data.get("label") == "Finding":
                fid = item_id.replace("finding:", "")
                findings.append({
                    "id": fid,
                    "summary": node_data.get("summary"),
                    "severity": node_data.get("severity"),
                    "snippet": node_data.get("snippet"),
                    "url": node_data.get("metadata", {}).get("url") or node_data.get("metadata", {}).get("endpoint"),
                    "distance": distance
                })
        
        return findings
    
    def _hybrid_retrieve(self, query: str, k: int) -> List[Dict[str, Any]]:
        """Hybrid: combines graph and vector search with ranking."""
        # Get candidates from both methods
        graph_results = self._graph_retrieve(query, k=k * 2)
        
        try:
            vector_results = self._vector_retrieve(query, k=k * 2)
        except RuntimeError:
            # Fallback to graph-only if vector search not available
            return graph_results[:k]
        
        # Merge results by ID and compute combined score
        merged = {}
        
        # Add graph results (higher weight for keyword matches)
        for idx, item in enumerate(graph_results):
            fid = item["id"]
            graph_score = len(graph_results) - idx  # Inverse rank
            merged[fid] = {
                **item,
                "graph_score": graph_score,
                "vector_score": 0
            }
        
        # Add vector results (semantic similarity)
        for idx, item in enumerate(vector_results):
            fid = item["id"]
            vector_score = len(vector_results) - idx  # Inverse rank
            
            if fid in merged:
                merged[fid]["vector_score"] = vector_score
            else:
                merged[fid] = {
                    **item,
                    "graph_score": 0,
                    "vector_score": vector_score
                }
        
        # Rank by combined score (graph + vector) and severity
        def sev_rank(s):
            order = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 10, "LOW": 5, "INFO": 1}
            return order.get(s.upper(), 1)
        
        ranked = sorted(
            merged.values(),
            key=lambda x: (
                -(x["graph_score"] + x["vector_score"]),
                -sev_rank(x.get("severity", "INFO"))
            )
        )
        
        # Return top-k without internal scores
        results = []
        for item in ranked[:k]:
            item.pop("graph_score", None)
            item.pop("vector_score", None)
            item.pop("distance", None)
            results.append(item)
        
        return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--graph", default=None)
    p.add_argument("--query", required=True)
    p.add_argument("--mode", default="graph", choices=["graph", "vector", "hybrid"])
    args = p.parse_args()
    
    # For vector/hybrid modes, would need to load embedder + vector_store
    # For now, just demonstrate graph mode
    r = Retriever(Path(args.graph) if args.graph else None)
    res = r.retrieve(args.query, k=5, mode=args.mode)
    print(res)

