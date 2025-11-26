"""
Complete Knowledge Graph implementation for RAG graph-based retrieval.
- Builds a NetworkX graph from scanner audit_report.json file
- Creates Finding, Endpoint, CWE, OWASP, Mitigation, AttackVector nodes
- Establishes rich relationships between security concepts
- Saves/loads graph as gpickle at rag/graph.gpickle

Full schema:
- Finding → found_at → Endpoint
- Finding → is_instance_of → CWE
- Finding → exploitable_via → AttackVector
- CWE → belongs_to → OWASP
- CWE → fixed_by → Mitigation
- Mitigation → demonstrates → CodeExample
- AttackVector → targets → Endpoint
"""
from __future__ import annotations
import json
from pathlib import Path
import hashlib
import networkx as nx
from typing import Dict, Any, Optional, List

GRAPH_PATH = Path(__file__).parent / "graph.gpickle"
CWE_MAP_PATH = Path(__file__).parent / "cwe_map.json"
OWASP_MAP_PATH = Path(__file__).parent / "owasp_map.json"


class KnowledgeGraph:
    def __init__(self):
        self.g = nx.DiGraph()
        self._cwe_mappings: List[Dict[str, Any]] = []
        self._owasp_categories: List[Dict[str, Any]] = []
        self._mitigations: List[Dict[str, Any]] = []
        self._cwe_to_owasp: Dict[str, List[str]] = {}
        self._load_knowledge_base()

    def _load_knowledge_base(self):
        """Load CWE mappings and OWASP categories from JSON files."""
        # Load CWE mappings
        if CWE_MAP_PATH.exists():
            with CWE_MAP_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
                self._cwe_mappings = data.get("mappings", [])
        
        # Load OWASP categories and mitigations
        if OWASP_MAP_PATH.exists():
            with OWASP_MAP_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
                self._owasp_categories = data.get("owasp_categories", [])
                self._mitigations = data.get("mitigations", [])
                
                # Build CWE → OWASP mapping
                for owasp in self._owasp_categories:
                    for cwe_id in owasp.get("cwes", []):
                        if cwe_id not in self._cwe_to_owasp:
                            self._cwe_to_owasp[cwe_id] = []
                        self._cwe_to_owasp[cwe_id].append(owasp["owasp_id"])
                
                # Add OWASP nodes to graph
                self._initialize_owasp_nodes()
                
                # Add Mitigation nodes to graph
                self._initialize_mitigation_nodes()

    def _initialize_owasp_nodes(self):
        """Create OWASP category nodes in the graph."""
        for owasp in self._owasp_categories:
            owasp_id = owasp["owasp_id"]
            node_id = f"owasp:{owasp_id}"
            self.g.add_node(
                node_id,
                label="OWASP",
                owasp_id=owasp_id,
                name=owasp["name"],
                description=owasp["description"],
                year=owasp["year"],
                rank=owasp["rank"]
            )

    def _initialize_mitigation_nodes(self):
        """Create Mitigation nodes in the graph."""
        for mit in self._mitigations:
            mit_id = mit["id"]
            node_id = f"mitigation:{mit_id}"
            self.g.add_node(
                node_id,
                label="Mitigation",
                mitigation_id=mit_id,
                name=mit["name"],
                description=mit["description"]
            )
            
            # Create CodeExample nodes and link them
            for example_file in mit.get("code_examples", []):
                example_id = hashlib.sha1(example_file.encode()).hexdigest()[:12]
                example_node = f"code_example:{example_id}"
                self.g.add_node(
                    example_node,
                    label="CodeExample",
                    filename=example_file,
                    mitigation_id=mit_id
                )
                # Edge: Mitigation → demonstrates → CodeExample
                self.g.add_edge(node_id, example_node, label="demonstrates")

    @staticmethod
    def _make_finding_id(f: Dict[str, Any]) -> str:
        """Create deterministic ID from finding data."""
        key = (f.get("type", "") + "|" + f.get("summary", "") + "|" + (f.get("snippet") or ""))
        return hashlib.sha1(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _make_endpoint_id(url: str, method: Optional[str] = None) -> str:
        """Create deterministic ID for endpoint."""
        key = (method or "") + "|" + url
        return hashlib.sha1(key.encode("utf-8")).hexdigest()

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding node and create relationships to CWE, OWASP, Attack Vectors."""
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
        finding_node = f"finding:{fid}"
        self.g.add_node(finding_node, label="Finding", **attrs)

        # 1. Add Endpoint node and relationship
        url = finding.get("url") or (finding.get("details") or {}).get("url")
        method = finding.get("method") or (finding.get("details") or {}).get("method")
        if url:
            eid = self._make_endpoint_id(url, method)
            endpoint_node = f"endpoint:{eid}"
            endpoint_attrs = {"url": url, "method": method}
            self.g.add_node(endpoint_node, label="Endpoint", **endpoint_attrs)
            # Edge: Finding → found_at → Endpoint
            self.g.add_edge(finding_node, endpoint_node, label="found_at")

        # 2. CWE enrichment: map finding type to CWE node
        finding_type = finding.get("type", "")
        pattern = finding.get("pattern") or finding.get("metadata", {}).get("pattern")
        
        matched_cwe = None
        for mapping in self._cwe_mappings:
            types_list = mapping.get("finding_types", [])
            if finding_type in types_list or pattern in types_list:
                matched_cwe = mapping
                cwe_id = mapping["cwe_id"]
                cwe_node = f"cwe:{cwe_id}"
                
                # Add CWE node if not exists
                if cwe_node not in self.g:
                    self.g.add_node(
                        cwe_node,
                        label="CWE",
                        cwe_id=cwe_id,
                        name=mapping.get("cwe_name"),
                        description=mapping.get("description"),
                        severity=mapping.get("severity")
                    )
                
                # Edge: Finding → is_instance_of → CWE
                self.g.add_edge(finding_node, cwe_node, label="is_instance_of")
                
                # 3. Link CWE → OWASP
                if cwe_id in self._cwe_to_owasp:
                    for owasp_id in self._cwe_to_owasp[cwe_id]:
                        owasp_node = f"owasp:{owasp_id}"
                        if owasp_node in self.g:
                            # Edge: CWE → belongs_to → OWASP
                            self.g.add_edge(cwe_node, owasp_node, label="belongs_to")
                
                # 4. Link CWE → Mitigation
                # Find relevant mitigations for this OWASP category
                for owasp_id in self._cwe_to_owasp.get(cwe_id, []):
                    owasp_data = next((o for o in self._owasp_categories if o["owasp_id"] == owasp_id), None)
                    if owasp_data:
                        for mit_id in owasp_data.get("mitigation_ids", []):
                            mit_node = f"mitigation:{mit_id}"
                            if mit_node in self.g:
                                # Edge: CWE → fixed_by → Mitigation
                                self.g.add_edge(cwe_node, mit_node, label="fixed_by")
                
                # 5. Add AttackVector nodes and relationships
                attack_vectors = mapping.get("attack_vectors", [])
                for av_name in attack_vectors:
                    av_id = hashlib.sha1(av_name.encode()).hexdigest()[:12]
                    av_node = f"attack_vector:{av_id}"
                    
                    if av_node not in self.g:
                        self.g.add_node(
                            av_node,
                            label="AttackVector",
                            name=av_name.replace("_", " ").title(),
                            attack_type=av_name
                        )
                    
                    # Edge: Finding → exploitable_via → AttackVector
                    self.g.add_edge(finding_node, av_node, label="exploitable_via")
                    
                    # Edge: AttackVector → targets → Endpoint (if endpoint exists)
                    if url:
                        endpoint_node = f"endpoint:{eid}"
                        if endpoint_node in self.g:
                            self.g.add_edge(av_node, endpoint_node, label="targets")
                
                break  # Use first matching CWE

    def build_from_audit(self, audit_path: Path):
        """Build graph from audit report JSON file."""
        if not audit_path.exists():
            raise FileNotFoundError(f"Audit file not found: {audit_path}")
        with audit_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        findings = data.get("findings", [])
        # Normalize findings to minimal schema
        for f in findings:
            normalized = {
                "id": f.get("id"),
                "type": f.get("type"),
                "severity": f.get("severity", "INFO"),
                "source": f.get("source") or f.get("client") or "mitm",
                "summary": f.get("summary") or f.get("description") or f.get("type"),
                "snippet": f.get("snippet"),
                "pattern": f.get("pattern"),
                "metadata": {k: v for k, v in f.items() if k not in ("type", "severity", "summary", "snippet", "pattern")},
                "url": f.get("url"),
                "method": f.get("method"),
                "timestamp": f.get("timestamp") or f.get("ts")
            }
            self.add_finding(normalized)

    def save(self, path: Optional[Path] = None):
        """Save graph to pickle file."""
        path = path or GRAPH_PATH
        try:
            nx.write_gpickle(self.g, path)
            return path
        except Exception:
            import pickle
            with open(path, "wb") as fh:
                pickle.dump(self.g, fh)
            return path

    def load(self, path: Optional[Path] = None):
        """Load graph from pickle file."""
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

    def stats(self) -> Dict[str, int]:
        """Get statistics about the graph."""
        findings = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "Finding"])
        endpoints = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "Endpoint"])
        cwes = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "CWE"])
        owasps = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "OWASP"])
        mitigations = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "Mitigation"])
        attack_vectors = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "AttackVector"])
        code_examples = len([n for n, d in self.g.nodes(data=True) if d.get("label") == "CodeExample"])
        edges = self.g.number_of_edges()
        
        return {
            "findings": findings,
            "endpoints": endpoints,
            "cwes": cwes,
            "owasps": owasps,
            "mitigations": mitigations,
            "attack_vectors": attack_vectors,
            "code_examples": code_examples,
            "edges": edges
        }


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
