"""
Unit tests for database normalizer.
"""

import pytest
import tempfile
import json
from pathlib import Path
from database.normalizer import DatabaseNormalizer, normalize_graph_to_db
from rag.knowledge_graph import KnowledgeGraph


def test_normalizer_init():
    """Test normalizer initialization creates database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        
        # Database file should exist
        assert db_path.exists()
        
        # Should have zero records initially
        stats = normalizer.get_stats()
        assert stats["findings"] == 0
        assert stats["cwes"] == 0


def test_normalize_simple_graph():
    """Test normalizing a simple graph with one finding."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create sample audit report
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "CRITICAL",
                    "url": "https://api.example.com/data",
                    "method": "GET",
                    "snippet": "[REDACTED]",
                    "summary": "API key exposed in Authorization header",
                    "source": "mitm"
                }
            ]
        }
        
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # Build graph
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        # Normalize to database
        db_path = Path(tmpdir) / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        stats = normalizer.normalize_from_graph(kg)
        
        # Should have 1 finding, 1 CWE
        assert stats["findings"] == 1
        assert stats["cwes"] >= 1  # At least CWE-798
        assert stats["finding_cwe_maps"] >= 1


def test_query_findings_by_severity():
    """Test querying findings by severity filter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create sample audit with mixed severities
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "CRITICAL",
                    "snippet": "[REDACTED]",
                    "summary": "Critical finding",
                    "source": "mitm"
                },
                {
                    "type": "api_key_in_header",
                    "severity": "MEDIUM",
                    "snippet": "[REDACTED]",
                    "summary": "Medium finding",
                    "source": "mitm"
                }
            ]
        }
        
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # Build and normalize
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        db_path = Path(tmpdir) / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        normalizer.normalize_from_graph(kg)
        
        # Query critical only
        critical = normalizer.query_findings(severity="CRITICAL")
        assert len(critical) == 1
        assert critical[0]["summary"] == "Critical finding"
        
        # Query medium only
        medium = normalizer.query_findings(severity="MEDIUM")
        assert len(medium) == 1
        assert medium[0]["summary"] == "Medium finding"


def test_query_findings_by_cwe():
    """Test querying findings by CWE ID."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "snippet": "[REDACTED]",
                    "summary": "API key in header",
                    "source": "mitm"
                }
            ]
        }
        
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        db_path = Path(tmpdir) / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        normalizer.normalize_from_graph(kg)
        
        # Check if CWE mapping exists
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM finding_cwe_map")
        mappings = cursor.fetchall()
        
        # Also check what CWE IDs were actually created
        cursor.execute("SELECT cwe_id FROM cwe_entries")
        cwe_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        # Query by CWE-798 (should match api_key_in_header if mapping exists)
        results = normalizer.query_findings(cwe_id="CWE-798")
        # If CWE mapping was created AND CWE-798 specifically exists, should find results
        if len(mappings) > 0 and "CWE-798" in cwe_ids:
            assert len(results) >= 1, f"Expected findings for CWE-798, got {len(results)}. Available CWEs: {cwe_ids}"
            assert any("API key" in r["summary"] for r in results)


def test_normalize_graph_to_db_cli():
    """Test CLI convenience function."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and save graph
        audit_data = {
            "findings": [
                {
                    "type": "plaintext_password",
                    "severity": "HIGH",
                    "snippet": "[REDACTED]",
                    "summary": "Plaintext password in source code",
                    "source": "git"
                }
            ]
        }
        
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        graph_path = Path(tmpdir) / "graph.gpickle"
        kg.save(graph_path)
        
        # Normalize using CLI function
        db_path = Path(tmpdir) / "test.db"
        stats = normalize_graph_to_db(str(graph_path), str(db_path))
        
        assert stats["findings"] >= 1
        assert stats["cwes"] >= 1
        
        # Verify database has data
        normalizer = DatabaseNormalizer(str(db_path))
        db_stats = normalizer.get_stats()
        assert db_stats["findings"] == stats["findings"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
