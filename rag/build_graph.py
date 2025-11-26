"""Small CLI wrapper to build and save the knowledge graph from an audit report."""
from pathlib import Path
from rag.knowledge_graph import KnowledgeGraph


def build_graph(audit_path: str = "audit_report.json", out: str | None = None) -> Path:
    audit = Path(audit_path)
    kg = KnowledgeGraph()
    kg.build_from_audit(audit)
    saved = kg.save(Path(out) if out else None)
    return saved


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--audit", default="audit_report.json")
    p.add_argument("--out", default=None)
    args = p.parse_args()
    out = build_graph(args.audit, args.out)
    print("Graph saved to:", out)
