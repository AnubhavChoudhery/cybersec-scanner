"""
CyberSec Scanner - A comprehensive security scanning and analysis library.

This library provides:
- Multi-source security scanning (git, web, browser, network)
- Knowledge graph-based vulnerability storage
- RAG (Retrieval Augmented Generation) for intelligent querying
- SQLite database for structured queries
- Modular SDK for independent scanner usage

Quick Start:
    >>> from cybersec_scanner import scan_git, scan_web
    >>> 
    >>> # Scan git repository
    >>> findings = scan_git("./my-repo", max_commits=10)
    >>> 
    >>> # Scan web application
    >>> from cybersec_scanner.scanners import LocalCrawler
    >>> crawler = LocalCrawler("http://localhost:8000")
    >>> crawler.run()

For CLI usage:
    $ cybersec-scanner scan --config config.yaml
    $ cybersec-scanner query "Show SQL injection findings"
"""

from .__version__ import (
    __version__,
    __version_info__,
    __title__,
    __description__,
    __author__,
    __license__,
)

# Core scanners - importable individually
from .scanners import (
    scan_git_history,
    LocalCrawler,
    process_crawler_findings,
    run_mitm_dump,
    stop_mitm_dump,
)

# RAG system
from .rag import (
    KnowledgeGraph,
    Retriever,
    generate_answer,
    query_graph_and_llm,
)

# Database
from .database import (
    DatabaseNormalizer,
    normalize_graph_to_db,
)

# Exceptions
from .exceptions import (
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

__all__ = [
    # Version
    "__version__",
    "__version_info__",
    "__title__",
    "__description__",
    "__author__",
    "__license__",
    
    # Scanners (can be used independently)
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
    
    # Convenience functions
    "scan_git",
    "scan_web",
    "scan_all",
]


# Convenience wrapper functions for common use cases
def scan_git(root_path: str, max_commits: int = 50, **kwargs):
    """
    Convenience function to scan git repository.
    
    Args:
        root_path: Path to git repository
        max_commits: Maximum commits to scan
        **kwargs: Additional options for git scanner
        
    Returns:
        List of findings
        
    Example:
        >>> findings = scan_git("./my-repo", max_commits=100)
        >>> print(f"Found {len(findings)} issues")
    """
    return scan_git_history(root_path, max_commits=max_commits, **kwargs)


def scan_web(target_url: str, max_pages: int = 50, **kwargs):
    """
    Convenience function to scan web application.
    
    Args:
        target_url: Target URL to scan
        max_pages: Maximum pages to crawl
        **kwargs: Additional options for web crawler
        
    Returns:
        List of findings
        
    Example:
        >>> findings = scan_web("http://localhost:8000")
        >>> print(f"Found {len(findings)} vulnerabilities")
    """
    crawler = LocalCrawler(target_url, max_pages=max_pages, **kwargs)
    crawler.run()
    return process_crawler_findings(crawler.findings)


def scan_all(config_file: str = None, **kwargs):
    """
    Run all enabled scanners based on configuration.
    
    Args:
        config_file: Path to YAML configuration file
        **kwargs: Override config options
        
    Returns:
        Dict with findings from all scanners
        
    Example:
        >>> results = scan_all("config.yaml")
        >>> print(f"Git: {len(results['git'])} findings")
        >>> print(f"Web: {len(results['web'])} findings")
    """
    from .cli.config import load_config
    
    config = load_config(config_file) if config_file else {}
    config.update(kwargs)
    
    results = {
        "git": [],
        "web": [],
        "mitm": [],
        "runtime": [],
    }
    
    # Git scan
    if config.get("enable_git", False):
        try:
            results["git"] = scan_git_history(
                config.get("root", "."),
                max_commits=config.get("max_commits", 50)
            )
        except Exception as e:
            raise ScannerError(f"Git scan failed: {e}")
    
    # Web scan
    if config.get("enable_web", False):
        try:
            target = config.get("target")
            if target:
                results["web"] = scan_web(target, max_pages=config.get("max_pages", 50))
        except Exception as e:
            raise ScannerError(f"Web scan failed: {e}")
    
    # MITM scan
    if config.get("enable_mitm", False):
        traffic_file = config.get("mitm_traffic")
        if traffic_file:
            # Process MITM traffic
            # Implementation depends on traffic file format
            pass
    
    return results
