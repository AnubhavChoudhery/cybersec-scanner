"""
Unit tests for LLM client with Ollama.

Prerequisites:
- Ollama installed and running
- At least one model available (gemma3:1b recommended for speed)

To skip these tests if Ollama is not available:
    pytest tests/ -v -k "not llm_client"
"""

import pytest
import requests
from rag.llm_client import (
    generate_answer,
    _redact_secrets,
    _ensure_citation,
    _build_prompt,
    OllamaError
)


def is_ollama_available():
    """Check if Ollama is running."""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


# Skip all tests in this module if Ollama not available
pytestmark = pytest.mark.skipif(
    not is_ollama_available(),
    reason="Ollama not running (start with: ollama serve)"
)


def test_redact_secrets():
    """Test secret redaction in responses."""
    text = "The API key is AKIAIOSFODNN7EXAMPLE and password is secret123"
    redacted = _redact_secrets(text)
    
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED]" in redacted
    assert "password is" in redacted  # Keep context


def test_ensure_citation():
    """Test citation enforcement in LLM responses."""
    contexts = [
        {"id": "f1", "summary": "API key in header", "severity": "CRITICAL"},
        {"id": "f2", "summary": "Password in code", "severity": "HIGH"}
    ]
    
    # Response without citations
    response = "There are security issues with credentials."
    cited = _ensure_citation(response, contexts)
    
    assert "[Source: f1]" in cited or "[Source: f2]" in cited
    

def test_build_prompt():
    """Test RAG prompt construction."""
    contexts = [
        {
            "id": "f1",
            "summary": "API key exposed in Authorization header",
            "severity": "CRITICAL",
            "snippet": "Authorization: Bearer xyz",
            "url": "https://api.example.com"
        }
    ]
    
    query = "What security issues were found?"
    prompt = _build_prompt(contexts, query)
    
    # Prompt should contain context
    assert "API key exposed" in prompt
    assert "CRITICAL" in prompt
    assert "https://api.example.com" in prompt
    
    # Prompt should contain query
    assert query in prompt
    
    # Prompt should have RAG instructions
    assert "context" in prompt.lower() or "finding" in prompt.lower()


def test_generate_answer_basic():
    """Test basic LLM answer generation with real Ollama call."""
    contexts = [
        {
            "id": "f1",
            "summary": "AWS API key exposed in HTTP header",
            "severity": "CRITICAL",
            "snippet": "Authorization: Bearer AKIAIOSFODNN7EXAMPLE",
            "url": "https://api.example.com/data"
        }
    ]
    
    query = "What critical security issues were found?"
    
    # This makes a real Ollama API call
    result = generate_answer(query, contexts, model="gemma3:1b", timeout=30)
    
    # Response should be a dict with text
    assert isinstance(result, dict)
    assert "text" in result
    response = result["text"]
    assert len(response) > 0
    
    # Response should reference the finding (either by keyword or citation)
    assert any(keyword in response.lower() for keyword in ["api", "key", "critical", "finding"])


def test_generate_answer_empty_context():
    """Test LLM handles empty context gracefully."""
    contexts = []
    query = "What issues were found?"
    
    result = generate_answer(query, contexts, model="gemma3:1b", timeout=30)
    
    # Should return something, even with no context
    assert isinstance(result, dict)
    response = result["text"]
    assert len(response) > 0


def test_generate_answer_multiple_findings():
    """Test LLM summarizes multiple findings."""
    contexts = [
        {
            "id": "f1",
            "summary": "API key in header",
            "severity": "CRITICAL",
            "snippet": "Authorization: Bearer xyz"
        },
        {
            "id": "f2",
            "summary": "Password in source code",
            "severity": "HIGH",
            "snippet": "password = 'secret123'"
        },
        {
            "id": "f3",
            "summary": "Sensitive data in localStorage",
            "severity": "MEDIUM",
            "snippet": "localStorage.setItem('token', 'xyz')"
        }
    ]
    
    query = "Summarize all security findings."
    
    result = generate_answer(query, contexts, model="gemma3:1b", timeout=30)
    
    # Response should mention multiple issues or severities
    response = result["text"]
    assert len(response) > 50  # Should be a substantial response
    # At least mention critical or high severity issues
    assert any(keyword in response.lower() for keyword in ["critical", "high", "multiple", "several", "api", "password"])


def test_ollama_error_handling():
    """Test error handling when Ollama fails."""
    contexts = [{"id": "f1", "summary": "Test", "severity": "HIGH"}]
    
    # Use invalid model name to trigger error
    with pytest.raises(OllamaError):
        generate_answer("test query", contexts, model="invalid_model_12345", timeout=5)


def test_generate_answer_timeout():
    """Test timeout handling."""
    contexts = [{"id": "f1", "summary": "Test finding", "severity": "HIGH"}]
    
    # Very short timeout should work or raise OllamaError (not hang)
    try:
        result = generate_answer("test", contexts, model="gemma3:1b", timeout=1)
        # If it completes fast enough, that's fine
        assert isinstance(result, dict)
    except OllamaError:
        # Timeout error is also acceptable
        pass


def test_answer_includes_severity():
    """Test LLM response acknowledges severity levels."""
    contexts = [
        {
            "id": "f1",
            "summary": "Critical vulnerability in authentication",
            "severity": "CRITICAL",
            "snippet": "Missing authentication check"
        }
    ]
    
    query = "How severe is this issue?"
    result = generate_answer(query, contexts, model="gemma3:1b", timeout=30)
    
    # Response should mention severity
    response = result["text"]
    assert "critical" in response.lower() or "severe" in response.lower() or "high" in response.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
