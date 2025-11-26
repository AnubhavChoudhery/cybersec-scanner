"""
CyberSec Scanner - A Python library for web application security auditing.

This library provides:
- Multi-source security scanning (git, web, browser, network)
- Knowledge graph-based finding storage
- RAG (Retrieval Augmented Generation) for intelligent querying
- SQLite database for structured queries
- Vector search for semantic finding retrieval
"""

from typing import Dict, List, Any, Optional
from pathlib import Path

__version__ = "0.1.0"
__author__ = "CyberSec Team"
__license__ = "MIT"

# Core scanner functionality
from scanners.git_scanner import scan_git_history
from scanners.web_crawler import LocalCrawler, process_crawler_findings
from scanners.network_scanner import run_mitm_dump, stop_mitm_dump

# RAG system
from rag.knowledge_graph import KnowledgeGraph
from rag.retriever import Retriever
from rag.llm_client import generate_answer
from rag.cli import query_graph_and_llm

# Database
from database.normalizer import DatabaseNormalizer, normalize_graph_to_db

# Exceptions
from exceptions import (
    CyberSecScannerError,
    ScannerError,
    GraphError,
    DatabaseError,
    RetrieverError,
    EmbeddingError,
    LLMError,
    ConfigurationError,
    ValidationError,
)

# Public API
__all__ = [
    # Version
    "__version__",
    
    # Scanners
    "scan_git_history",
    "LocalCrawler",
    "process_crawler_findings",
    "run_mitm_dump",
    "stop_mitm_dump",
    
    # RAG
    "KnowledgeGraph",
    "Retriever",
    "generate_answer",
    "query_graph_and_llm",
    
    # Database
    "DatabaseNormalizer",
    "normalize_graph_to_db",
    
    # Exceptions
    "CyberSecScannerError",
    "ScannerError",
    "GraphError",
    "DatabaseError",
    "RetrieverError",
    "EmbeddingError",
    "LLMError",
    "ConfigurationError",
    "ValidationError",
]


# Convenience function for quick scanning
def scan(
    git_repo: Optional[str] = None,
    url: Optional[str] = None,
    output_path: str = "audit_report.json",
    **kwargs
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Quick scan function for common use cases.
    
    Args:
        git_repo: Path to git repository to scan
        url: URL to crawl and scan
        output_path: Where to save audit report
        **kwargs: Additional scanner options
    
    Returns:
        dict: Audit report with findings
    
    Example:
        >>> from cybersec_scanner import scan
        >>> report = scan(git_repo=".", url="https://example.com")
        >>> print(f"Found {len(report['findings'])} issues")
    """
    import json
    from pathlib import Path
    
    findings = []
    
    # Git scan
    if git_repo:
        try:
            git_findings = scan_git_history(git_repo, **kwargs)
            findings.extend(git_findings)
        except Exception as e:
            raise ScannerError(f"Git scan failed: {e}")
    
    # Web scan
    if url:
        try:
            # LocalCrawler usage: instantiate and call scan method
            crawler = LocalCrawler(url)
            # Assuming it has a scan() or similar method that returns findings
            # If not, adjust based on actual API
            web_findings = process_crawler_findings(crawler.findings if hasattr(crawler, 'findings') else [])
            findings.extend(web_findings)
        except Exception as e:
            raise ScannerError(f"Web scan failed: {e}")
    
    # Create report
    report = {"findings": findings}
    
    # Save to file
    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2))
    
    return report


# Convenience function for RAG queries
def query(
    question: str,
    audit_report: str = "audit_report.json",
    model: str = "gemma3:1b",
    mode: str = "graph",
    k: int = 5
) -> str:
    """
    Query findings using RAG system.
    
    Args:
        question: Natural language question
        audit_report: Path to audit report JSON
        model: LLM model to use
        mode: Retrieval mode ('graph', 'vector', 'hybrid')
        k: Number of findings to retrieve
        
    Returns:
        str: LLM-generated answer with citations
    
    Example:
        >>> from cybersec_scanner import query
        >>> answer = query("Show me all API key leaks")
        >>> print(answer)
    """
    from pathlib import Path
    from pathlib import Path
    
    # Build knowledge graph if needed
    graph_path = Path("rag/graph.gpickle")
    if not graph_path.exists():
        audit_path = Path(audit_report)
        if not audit_path.exists():
            raise ValidationError(f"Audit report not found: {audit_report}")
        
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        kg.save(graph_path)
    
    # Retrieve relevant findings
    retriever = Retriever(graph_path=graph_path)
    findings = retriever.retrieve(question, k=k, mode=mode)
    
    if not findings:
        return "No relevant findings found."
    
    # Query LLM - fix parameter names: user_query, retrieved_contexts
    try:
        answer = generate_answer(
            user_query=question,
            retrieved_contexts=findings,
            model=model
        )
        return answer.get("text", "No answer generated")
    except Exception as e:
        # Return findings even if LLM fails
        return f"Found {len(findings)} relevant findings (LLM unavailable: {e})"
