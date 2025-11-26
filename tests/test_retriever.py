"""
Unit tests for graph-based retriever.
"""

import pytest
import tempfile
import json
from pathlib import Path
from rag.retriever import Retriever, _tokenize
from rag.knowledge_graph import KnowledgeGraph


def test_tokenize():
    """Test query tokenization filters short tokens."""
    tokens = _tokenize("API key in header")
    assert "api" in tokens
    assert "key" in tokens
    assert "header" in tokens
    assert "in" not in tokens  # Too short (< 3 chars)
    
    # Test special characters - tokenizer keeps words together (\w+ pattern)
    tokens = _tokenize("AWS_ACCESS_KEY-123")
    assert "aws_access_key" in tokens  # Underscores kept together
    assert "123" in tokens


def test_retriever_empty_graph():
    """Test retriever with empty graph returns empty results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create empty audit
        audit_data = {"findings": []}
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        # Build empty graph
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        graph_path = Path(tmpdir) / "graph.gpickle"
        kg.save(graph_path)
        
        # Retrieve should return empty
        retriever = Retriever(graph_path=graph_path)
        results = retriever.retrieve("anything", k=5)
        assert len(results) == 0


def test_retriever_keyword_matching():
    """Test retriever matches keywords in summary and snippet."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create audit with specific keywords
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "CRITICAL",
                    "summary": "AWS API key exposed in Authorization header",
                    "snippet": "Authorization: Bearer AKIAIOSFODNN7EXAMPLE",
                    "source": "mitm"
                },
                {
                    "type": "plaintext_password",
                    "severity": "HIGH",
                    "summary": "Database password in configuration file",
                    "snippet": "db_password = 'secret123'",
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
        
        retriever = Retriever(graph_path=graph_path)
        
        # Query for API key (matches "api" and "key" tokens in summary)
        results = retriever.retrieve("api key", k=5)
        assert len(results) >= 1
        assert any("key" in r["summary"].lower() for r in results)
        
        # Query for password
        results = retriever.retrieve("database password", k=5)
        assert len(results) >= 1
        assert any("password" in r["summary"].lower() for r in results)
        
        # Query that matches both findings ("exposed" in first, "configuration" in second)
        results = retriever.retrieve("exposed configuration", k=5)
        assert len(results) >= 1


def test_retriever_severity_ranking():
    """Test retriever ranks CRITICAL above HIGH above MEDIUM."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create audit with mixed severities, same keyword
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "MEDIUM",
                    "summary": "API key in localStorage",
                    "snippet": "localStorage.setItem('api_key', 'xyz')",
                    "source": "browser"
                },
                {
                    "type": "api_key_in_header",
                    "severity": "CRITICAL",
                    "summary": "API key transmitted over HTTP",
                    "snippet": "http://example.com?key=xyz",
                    "source": "mitm"
                },
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "summary": "API key in URL parameter",
                    "snippet": "https://example.com?apiKey=xyz",
                    "source": "web"
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
        
        retriever = Retriever(graph_path=graph_path)
        
        # Query should rank by severity
        results = retriever.retrieve("API key", k=3)
        assert len(results) == 3
        
        # CRITICAL should be first
        assert results[0]["severity"] == "CRITICAL"
        # HIGH should be second
        assert results[1]["severity"] == "HIGH"
        # MEDIUM should be last
        assert results[2]["severity"] == "MEDIUM"


def test_retriever_k_limit():
    """Test retriever respects k parameter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create audit with 5 findings
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "summary": f"Finding {i}",
                    "snippet": "secret",
                    "source": "mitm"
                }
                for i in range(5)
            ]
        }
        
        audit_path = Path(tmpdir) / "audit.json"
        with open(audit_path, 'w') as f:
            json.dump(audit_data, f)
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        graph_path = Path(tmpdir) / "graph.gpickle"
        kg.save(graph_path)
        
        retriever = Retriever(graph_path=graph_path)
        
        # Request only 3 results
        results = retriever.retrieve("Finding", k=3)
        assert len(results) == 3
        
        # Request all 5
        results = retriever.retrieve("Finding", k=5)
        assert len(results) == 5
        
        # Request more than available
        results = retriever.retrieve("Finding", k=10)
        assert len(results) == 5  # Should return only 5


def test_retriever_no_match():
    """Test retriever returns empty list when no keywords match."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "summary": "API key in header",
                    "snippet": "Authorization: Bearer xyz",
                    "source": "mitm"
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
        
        retriever = Retriever(graph_path=graph_path)
        
        # Query with completely unrelated terms
        results = retriever.retrieve("database SQL injection", k=5)
        assert len(results) == 0


def test_retriever_case_insensitive():
    """Test retriever is case-insensitive."""
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_data = {
            "findings": [
                {
                    "type": "api_key_in_header",
                    "severity": "HIGH",
                    "summary": "AWS Access Key Exposed",
                    "snippet": "AKIAIOSFODNN7EXAMPLE",
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
        
        retriever = Retriever(graph_path=graph_path)
        
        # Test different cases
        results_lower = retriever.retrieve("aws access key", k=5)
        results_upper = retriever.retrieve("AWS ACCESS KEY", k=5)
        results_mixed = retriever.retrieve("Aws Access Key", k=5)
        
        assert len(results_lower) >= 1
        assert len(results_upper) >= 1
        assert len(results_mixed) >= 1
        
        # All should return same result
        assert results_lower[0]["summary"] == results_upper[0]["summary"]
        assert results_lower[0]["summary"] == results_mixed[0]["summary"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
