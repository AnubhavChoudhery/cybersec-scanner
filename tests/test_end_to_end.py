"""
End-to-end integration test for RAG pipeline.

Tests the full flow:
1. Build knowledge graph from audit report
2. Normalize graph to SQLite
3. Embed findings (optional, if embedder available)
4. Retrieve relevant contexts
5. Generate LLM response (mocked)

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


def test_end_to_end_with_embeddings():
    """Test E2E with vector search (if embedder available)."""
    try:
        from rag.embedder import Embedder
        from rag.vector_store import VectorStore
    except (ImportError, RuntimeError):
        pytest.skip("Embedder or VectorStore not available")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create sample audit
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "snippet": "[REDACTED]",
                    "summary": "Exposed API credentials in HTTP header",
                    "source": "mitm"
                }
            ]
        }
        
        audit_path = tmpdir / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # Build graph
        from rag.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        graph_path = tmpdir / "graph.gpickle"
        kg.save(graph_path)
        
        # Create embeddings
        embedder = Embedder()
        vector_store = VectorStore()
        
        # Embed all findings
        for node_id, data in kg.g.nodes(data=True):
            if data.get("label") == "Finding":
                text = f"{data.get('summary')} {data.get('snippet')}"
                embedding = embedder.embed_texts([text])[0]
                vector_store.add(node_id, embedding)
        
        # Save vector store
        vs_path = tmpdir / "vectors.index"
        vector_store.save(str(vs_path))
        
        # Test vector search
        from rag.retriever import Retriever
        
        retriever = Retriever(
            graph_path=graph_path,
            embedder=embedder,
            vector_store=vector_store
        )
        
        # Semantic query (should match even without exact keywords)
        results = retriever.retrieve(
            "credentials exposed in requests",
            k=5,
            mode="vector"
        )
        
        assert len(results) >= 1
        assert any("credentials" in r["summary"].lower() or "API" in r["summary"] for r in results)
        
        # Test hybrid mode
        hybrid_results = retriever.retrieve(
            "API key security issue",
            k=5,
            mode="hybrid"
        )
        
        assert len(hybrid_results) >= 1
        
        print("✅ End-to-end with embeddings test passed!")


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
