import json
import tempfile
from pathlib import Path
from rag.knowledge_graph import KnowledgeGraph


def test_cwe_enrichment(tmp_path):
    # Create a sample audit with an AWS key finding
    audit = tmp_path / "audit_report.json"
    content = {
        "timestamp": "2025-11-26T00:00:00",
        "target": "http://localhost:8000",
        "findings": [
            {
                "type": "api_key_in_header",
                "severity": "HIGH",
                "source": "mitm",
                "description": "AWS_ACCESS_KEY in Authorization header",
                "url": "https://api.example.com/v1/data",
                "method": "POST",
                "pattern": "AWS_ACCESS_KEY"
            }
        ]
    }
    audit.write_text(json.dumps(content))

    kg = KnowledgeGraph()
    kg.build_from_audit(audit)
    stats = kg.stats()

    # Should have 1 finding, 1 endpoint, and 1 CWE node
    assert stats["findings"] == 1
    assert stats["endpoints"] == 1
    assert stats["cwes"] == 1

    # Find the CWE node and verify it's CWE-798
    cwe_nodes = [n for n, d in kg.g.nodes(data=True) if d.get("label") == "CWE"]
    assert len(cwe_nodes) == 1
    cwe_data = kg.g.nodes[cwe_nodes[0]]
    assert cwe_data["cwe_id"] == "CWE-798"
    assert "Hard-coded Credentials" in cwe_data["name"]

    # Verify the finding has an is_instance_of edge to the CWE
    finding_nodes = [n for n, d in kg.g.nodes(data=True) if d.get("label") == "Finding"]
    assert len(finding_nodes) == 1
    edges = list(kg.g.out_edges(finding_nodes[0], data=True))
    cwe_edges = [e for e in edges if e[2].get("label") == "is_instance_of"]
    assert len(cwe_edges) == 1
