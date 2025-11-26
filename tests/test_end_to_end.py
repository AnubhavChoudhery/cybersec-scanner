"""
End-to-end integration test for RAG pipeline.

Tests the full flow:
1. Build knowledge graph from audit report
2. Normalize graph to SQLite
3. Retrieve relevant contexts using graph-based search
4. Generate LLM response (mocked)

Uses sample test data for fast execution.
"""

import pytest
import tempfile
import json
from pathlib import Path


def test_end_to_end_pipeline():
    """Test complete RAG pipeline with sample data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # 1. Create sample audit report
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "pattern": "GROQ_API_KEY",
                    "severity": "CRITICAL",
                    "url": "https://api.groq.com/openai/v1/chat/completions",
                    "method": "POST",
                    "snippet": "[REDACTED]",
                    "summary": "API key exposed in Authorization header",
                    "source": "mitm"
                },
                {
                    "type": "plaintext_password",
                    "severity": "HIGH",
                    "snippet": "[REDACTED]",
                    "summary": "Plaintext password in source code",
                    "source": "git"
                },
                {
                    "type": "browser_storage",
                    "severity": "MEDIUM",
                    "snippet": "[REDACTED]",
                    "summary": "Sensitive data in localStorage",
                    "source": "browser"
                }
            ]
        }
        
        audit_path = tmpdir / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # 2. Build knowledge graph with full schema
        from rag.knowledge_graph import KnowledgeGraph
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        # Verify graph has findings and enriched nodes
        stats = kg.stats()
        assert stats["findings"] == 3, f"Should have 3 findings, got {stats['findings']}"
        assert stats["cwes"] >= 2, f"Should have at least 2 CWEs, got {stats['cwes']}"
        assert stats["owasps"] >= 1, f"Should have OWASP nodes, got {stats['owasps']}"
        assert stats["mitigations"] >= 1, f"Should have mitigation nodes, got {stats['mitigations']}"
        
        # Verify edges exist
        assert stats["edges"] >= 3, "Should have multiple edges connecting nodes"
        
        # Save graph
        graph_path = tmpdir / "graph.gpickle"
        kg.save(graph_path)
        assert graph_path.exists()
        
        # 3. Normalize to SQLite
        from database.normalizer import DatabaseNormalizer
        
        db_path = tmpdir / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        norm_stats = normalizer.normalize_from_graph(kg)
        
        assert norm_stats["findings"] == 3
        assert norm_stats["cwes"] >= 2
        
        # Verify database queries work
        critical = normalizer.query_findings(severity="CRITICAL")
        assert len(critical) == 1
        assert "Authorization header" in critical[0]["summary"]
        
        high = normalizer.query_findings(severity="HIGH")
        assert len(high) == 1
        assert "password" in high[0]["summary"].lower()
        
        medium = normalizer.query_findings(severity="MEDIUM")
        assert len(medium) == 1
        assert "localStorage" in medium[0]["summary"]
        
        # 4. Test graph-based retrieval
        from rag.retriever import Retriever
        
        retriever = Retriever(graph_path=graph_path)
        
        # Query for API keys
        results = retriever.retrieve("API key exposure", k=5)
        assert len(results) >= 1
        assert any("API key" in r["summary"] for r in results)
        
        # Query for passwords
        results = retriever.retrieve("plaintext password", k=5)
        assert len(results) >= 1
        assert any("password" in r["summary"].lower() for r in results)
        
        # Query by keyword that exists in summary
        results = retriever.retrieve("authorization", k=5)
        assert len(results) >= 1
        # CRITICAL findings should be ranked first by severity
        if results:
            assert results[0]["severity"] in ["CRITICAL", "HIGH"]
        
        # Query for storage issues
        results = retriever.retrieve("localStorage sensitive", k=5)
        assert len(results) >= 1
        
        # 5. Verify graph traversal capabilities
        # Check that we can traverse from Finding → CWE → OWASP → Mitigation
        finding_nodes = [n for n, d in kg.g.nodes(data=True) if d.get("label") == "Finding"]
        assert len(finding_nodes) == 3
        
        # Check at least one finding has CWE link
        has_cwe_link = False
        for finding_node in finding_nodes:
            successors = list(kg.g.successors(finding_node))
            cwe_successors = [n for n in successors if n.startswith("cwe:")]
            if cwe_successors:
                has_cwe_link = True
                # Check CWE has OWASP link
                for cwe_node in cwe_successors:
                    owasp_links = [n for n in kg.g.successors(cwe_node) if n.startswith("owasp:")]
                    if owasp_links:
                        print(f"✅ Found complete path: {finding_node} → {cwe_node} → {owasp_links[0]}")
                        break
        
        assert has_cwe_link, "At least one finding should link to CWE"
        
        # 6. Verify end-to-end pipeline completed successfully
        assert graph_path.exists(), "Graph should be saved"
        assert db_path.exists(), "Database should be created"
        assert len(retriever.retrieve("API", k=10)) > 0, "Retriever should find results"
        
        print("✅ End-to-end pipeline test passed!")
        print(f"   Graph stats: {stats}")


def test_end_to_end_empty_audit():
    """Test pipeline handles empty audit gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create empty audit
        audit_data = {"findings": []}
        audit_path = tmpdir / "empty_audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        from rag.knowledge_graph import KnowledgeGraph
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        stats = kg.stats()
        assert stats["findings"] == 0
        # Should still have OWASP and Mitigation nodes from knowledge base
        assert stats["owasps"] >= 10, "Should have OWASP Top 10"
        assert stats["mitigations"] >= 5, "Should have mitigation library"
        
        # Save should work even with no findings
        graph_path = tmpdir / "empty_graph.gpickle"
        kg.save(graph_path)
        assert graph_path.exists()
        
        # Retrieval should return empty results
        from rag.retriever import Retriever
        retriever = Retriever(graph_path=graph_path)
        results = retriever.retrieve("anything", k=5)
        assert len(results) == 0, "Should return no results for empty graph"
        
        print("✅ Empty audit test passed!")


if __name__ == "__main__":
    test_end_to_end_pipeline()
    test_end_to_end_empty_audit()
    print("\n✅ All end-to-end tests passed!")

    """Test complete RAG pipeline with sample data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # 1. Create sample audit report
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "CRITICAL",
                    "url": "https://api.groq.com/openai/v1/chat/completions",
                    "method": "POST",
                    "snippet": "[REDACTED]",
                    "summary": "API key exposed in Authorization header",
                    "source": "mitm"
                },
                {
                    "type": "plaintext_password",
                    "severity": "HIGH",
                    "snippet": "[REDACTED]",
                    "summary": "Plaintext password in source code",
                    "source": "git"
                }
            ]
        }
        
        audit_path = tmpdir / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # 2. Build knowledge graph
        from rag.knowledge_graph import KnowledgeGraph
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        # Verify graph has findings
        stats = kg.stats()
        assert stats["findings"] == 2, "Should have 2 findings"
        assert stats["cwes"] >= 1, "Should have at least 1 CWE"
        
        # Save graph
        graph_path = tmpdir / "graph.gpickle"
        kg.save(graph_path)
        assert graph_path.exists()
        
        # 3. Normalize to SQLite
        from database.normalizer import DatabaseNormalizer
        
        db_path = tmpdir / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        norm_stats = normalizer.normalize_from_graph(kg)
        
        assert norm_stats["findings"] == 2
        assert norm_stats["cwes"] >= 1
        
        # Verify database queries work
        critical = normalizer.query_findings(severity="CRITICAL")
        assert len(critical) == 1
        assert "Authorization header" in critical[0]["summary"]
        
        high = normalizer.query_findings(severity="HIGH")
        assert len(high) == 1
        assert "password" in high[0]["summary"].lower()
        
        # 4. Test retrieval
        from rag.retriever import Retriever
        
        retriever = Retriever(graph_path=graph_path)
        
        # Query for API keys
        results = retriever.retrieve("API key exposure", k=5, mode="graph")
        assert len(results) >= 1
        assert any("API key" in r["summary"] for r in results)
        
        # Query for passwords
        results = retriever.retrieve("plaintext password", k=5, mode="graph")
        assert len(results) >= 1
        assert any("password" in r["summary"].lower() for r in results)
        
        # Query by keyword that exists in summary
        results = retriever.retrieve("authorization", k=5, mode="graph")
        assert len(results) >= 1
        # CRITICAL findings should be ranked first by severity
        if results:
            assert results[0]["severity"] in ["CRITICAL", "HIGH"]
        
        # 5. Verify end-to-end pipeline completed successfully
        assert graph_path.exists(), "Graph should be saved"
        assert db_path.exists(), "Database should be created"
        assert len(retriever.retrieve("API", k=10)) > 0, "Retriever should find results"
        
        print("✅ End-to-end pipeline test passed!")


def test_end_to_end_empty_audit():
    """Test E2E handles empty audit gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Empty audit
        audit_data = {
            "findings": []
        }
        
        audit_path = tmpdir / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        from rag.knowledge_graph import KnowledgeGraph
        from database.normalizer import DatabaseNormalizer
        from rag.retriever import Retriever
        
        # Build graph (should be empty)
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        stats = kg.stats()
        
        assert stats["findings"] == 0
        
        # Normalize (should handle empty graph)
        db_path = tmpdir / "test.db"
        normalizer = DatabaseNormalizer(str(db_path))
        norm_stats = normalizer.normalize_from_graph(kg)
        
        assert norm_stats["findings"] == 0
        
        # Retrieve (should return empty results)
        graph_path = tmpdir / "graph.gpickle"
        kg.save(graph_path)
        
        retriever = Retriever(graph_path=graph_path)
        results = retriever.retrieve("anything", k=5)
        
        assert len(results) == 0
        
        print("✅ Empty audit handling test passed!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
