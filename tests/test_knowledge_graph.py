import json
import tempfile
from pathlib import Path
from rag.knowledge_graph import KnowledgeGraph


def test_build_and_save_graph(tmp_path):
    # Create a minimal audit_report.json with one finding
    audit = tmp_path / "audit_report.json"
    content = {
        "timestamp": "2025-11-26T00:00:00",
        "target": "http://localhost:8000",
        "findings": [
            {
                "type": "api_key_in_header",
                "severity": "HIGH",
                "source": "mitm",
                "description": "GITHUB_PAT in Authorization header",
                "url": "https://api.github.com/repos/example",
                "method": "POST",
                "pattern": "GITHUB_PAT"
            }
        ]
    }
    audit.write_text(json.dumps(content))

    kg = KnowledgeGraph()
    kg.build_from_audit(audit)
    out = tmp_path / "graph.gpickle"
    kg.save(out)

    # Verify gpickle exists and has expected stats
    assert out.exists()
    kg2 = KnowledgeGraph()
    kg2.load(out)
    stats = kg2.stats()
    assert stats["findings"] == 1
    assert stats["endpoints"] == 1
    assert stats["edges"] >= 1
