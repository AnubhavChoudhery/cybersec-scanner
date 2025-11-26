"""
Lightweight Knowledge Graph implementation for RAG graph-phase.
- Builds a NetworkX graph from a scanner `audit_report.json` file
- Creates `Finding` and `Endpoint` nodes and links them (`found_at`)
- Saves/loads graph as a gpickle at `rag/graph.gpickle`

This is intentionally minimal so you can iterate quickly. It provides
APIs used by `rag/build_graph.py` and tests.
"""
from __future__ import annotations
import json
from pathlib import Path
import hashlib
import networkx as nx
from typing import Dict, Any, Optional, List

GRAPH_PATH = Path(__file__).parent / "graph.gpickle"
CWE_MAP_PATH = Path(__file__).parent / "cwe_map.json"


class KnowledgeGraph:
    def __init__(self):
        self.g = nx.DiGraph()
        self._cwe_mappings: List[Dict[str, Any]] = []
        self._load_cwe_map()

    def _load_cwe_map(self):
        if CWE_MAP_PATH.exists():
            with CWE_MAP_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
                self._cwe_mappings = data.get("mappings", [])

    @staticmethod
    def _make_finding_id(f: Dict[str, Any]) -> str:
        # Create deterministic id from type + summary + snippet
        key = (f.get("type", "") + "|" + f.get("summary", "") + "|" + (f.get("snippet") or ""))
        return hashlib.sha1(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _make_endpoint_id(url: str, method: Optional[str] = None) -> str:
        key = (method or "") + "|" + url
        return hashlib.sha1(key.encode("utf-8")).hexdigest()

    def add_finding(self, finding: Dict[str, Any]):
        fid = finding.get("id") or self._make_finding_id(finding)
        attrs = {
            "type": finding.get("type"),
            "severity": finding.get("severity", "INFO"),
            "source": finding.get("source"),
            "summary": finding.get("summary") or finding.get("description") or "",
            "snippet": finding.get("snippet"),
            "metadata": finding.get("metadata") or {},
            "timestamp": finding.get("timestamp") or finding.get("ts")
        }
        self.g.add_node(f"finding:{fid}", label="Finding", **attrs)

        # If the finding has a URL, add endpoint node and edge
        url = finding.get("url") or (finding.get("details") or {}).get("url")
        method = finding.get("method") or (finding.get("details") or {}).get("method")
        if url:
            eid = self._make_endpoint_id(url, method)
            endpoint_attrs = {"url": url, "method": method}
            self.g.add_node(f"endpoint:{eid}", label="Endpoint", **endpoint_attrs)
            # Edge: Finding -> found_at -> Endpoint
            self.g.add_edge(f"finding:{fid}", f"endpoint:{eid}", label="found_at")

        # CWE enrichment: map finding type to CWE node
        finding_type = finding.get("type", "")
        pattern = finding.get("pattern") or finding.get("metadata", {}).get("pattern")
        for mapping in self._cwe_mappings:
            types_list = mapping.get("finding_types", [])
            if finding_type in types_list or pattern in types_list:
                cwe_id = mapping["cwe_id"]
                cwe_node = f"cwe:{cwe_id}"
                if cwe_node not in self.g:
                    self.g.add_node(cwe_node, label="CWE", cwe_id=cwe_id, name=mapping.get("cwe_name"), description=mapping.get("description"), severity=mapping.get("severity"))
                self.g.add_edge(f"finding:{fid}", cwe_node, label="is_instance_of")
                break

    def build_from_audit(self, audit_path: Path):
        if not audit_path.exists():
            raise FileNotFoundError(f"Audit file not found: {audit_path}")
        with audit_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        findings = data.get("findings", [])
        # If older scanner created flat findings, normalize minimal fields
        for f in findings:
            # Ensure minimal schema conformity
            normalized = {
                "id": f.get("id"),
                "type": f.get("type"),
                "severity": f.get("severity", "INFO"),
                "source": f.get("source") or f.get("client") or "mitm",
                "summary": f.get("summary") or f.get("description") or f.get("type"),
                "snippet": f.get("snippet"),
                "metadata": {k: v for k, v in f.items() if k not in ("type", "severity", "summary", "snippet")},
                "url": f.get("url"),
                "method": f.get("method")
            }
            self.add_finding(normalized)

    def save(self, path: Optional[Path] = None):
        path = path or GRAPH_PATH
        # Some networkx installs may not expose write_gpickle/read_gpickle helpers.
        # Use networkx helpers when available, otherwise fall back to plain pickle
        # which works because NetworkX graphs are pickleable.
        try:
            nx.write_gpickle(self.g, path)
            return path
        except Exception:
            import pickle
            with open(path, "wb") as fh:
                pickle.dump(self.g, fh)
            return path
        return path

    def load(self, path: Optional[Path] = None):
        path = path or GRAPH_PATH
        if not Path(path).exists():
            raise FileNotFoundError(path)
        try:
            self.g = nx.read_gpickle(path)
            return self.g
        except Exception:
            import pickle
            with open(path, "rb") as fh:
                self.g = pickle.load(fh)
            return self.g
        return self.g

    def stats(self) -> Dict[str, int]:
        findings = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "Finding"])
        endpoints = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "Endpoint"])
        cwes = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "CWE"])
        edges = self.g.number_of_edges()
        return {"findings": findings, "endpoints": endpoints, "cwes": cwes, "edges": edges}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Build knowledge graph from audit_report.json")
    p.add_argument("--audit", default="audit_report.json", help="Path to audit_report.json")
    p.add_argument("--out", default=str(GRAPH_PATH), help="Output graph path (gpickle)")
    args = p.parse_args()

    kg = KnowledgeGraph()
    kg.build_from_audit(Path(args.audit))
    out = kg.save(Path(args.out))
    print(f"Saved graph to {out}")
    print("Stats:", kg.stats())
