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

# Lazy imports to avoid dependency errors during CLI usage
def __getattr__(name):
    """Lazy import for heavy dependencies."""
    if name in ["scan_git_history", "LocalCrawler", "process_crawler_findings", 
                "run_mitm_dump", "stop_mitm_dump"]:
        from .scanners import (
            scan_git_history,
            LocalCrawler,
            process_crawler_findings,
            run_mitm_dump,
            stop_mitm_dump,
        )
        globals().update({
            "scan_git_history": scan_git_history,
            "LocalCrawler": LocalCrawler,
            "process_crawler_findings": process_crawler_findings,
            "run_mitm_dump": run_mitm_dump,
            "stop_mitm_dump": stop_mitm_dump,
        })
        return globals()[name]
    
    elif name in ["KnowledgeGraph", "Retriever", "generate_answer", "query_graph_and_llm"]:
        from .rag import (
            KnowledgeGraph,
            Retriever,
            generate_answer,
            query_graph_and_llm,
        )
        globals().update({
            "KnowledgeGraph": KnowledgeGraph,
            "Retriever": Retriever,
            "generate_answer": generate_answer,
            "query_graph_and_llm": query_graph_and_llm,
        })
        return globals()[name]
    
    elif name in ["DatabaseNormalizer", "normalize_graph_to_db"]:
        from .database import (
            DatabaseNormalizer,
            normalize_graph_to_db,
        )
        globals().update({
            "DatabaseNormalizer": DatabaseNormalizer,
            "normalize_graph_to_db": normalize_graph_to_db,
        })
        return globals()[name]
    
    elif name in ["CyberSecScannerError", "ScannerError", "GraphError", "DatabaseError",
                  "RetrieverError", "EmbeddingError", "LLMError", "ConfigurationError",
                  "ValidationError"]:
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
        globals().update({
            "CyberSecScannerError": CyberSecScannerError,
            "ScannerError": ScannerError,
            "GraphError": GraphError,
            "DatabaseError": DatabaseError,
            "RetrieverError": RetrieverError,
            "EmbeddingError": EmbeddingError,
            "LLMError": LLMError,
            "ConfigurationError": ConfigurationError,
            "ValidationError": ValidationError,
        })
        return globals()[name]
    
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

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
    "scan_mitm",
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
    from .scanners import scan_git_history
    return scan_git_history(root_path, max_commits=max_commits, **kwargs)


def scan_mitm(traffic_file: str, **kwargs):
    """
    Convenience function to scan MITM proxy traffic.
    
    Args:
        traffic_file: Path to NDJSON traffic file
        **kwargs: Additional options for MITM scanner
        
    Returns:
        List of findings
        
    Example:
        >>> findings = scan_mitm("mitm_traffic.ndjson")
        >>> print(f"Found {len(findings)} secrets in traffic")
    """
    from .scanners import parse_mitm_traffic
    return parse_mitm_traffic(traffic_file, **kwargs)


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
    from .scanners import LocalCrawler, process_crawler_findings
    crawler = LocalCrawler(target_url, max_pages=max_pages, **kwargs)
    crawler.crawl()
    return process_crawler_findings(crawler.findings)


def scan_mitm(traffic_file: str, start_proxy: bool = False, port: int = 8082, **kwargs):
    """
    Run full MITM workflow: inject proxy, capture traffic, parse findings.
    
    Args:
        traffic_file: Path to NDJSON traffic file (will be created/cleared)
        start_proxy: If True, start mitmproxy daemon and inject HTTP client patches
        port: MITM proxy port (default: 8082)
        **kwargs: Additional options
        
    Returns:
        Dict with security_findings, traffic_findings, proxied, bypassed counts
        
    Example (parse existing traffic):
        >>> findings = scan_mitm("./mitm_traffic.ndjson")
        
    Example (full workflow with proxy):
        >>> from cybersec_scanner.scanners.inject_mitm_proxy import inject_mitm_proxy_advanced
        >>> inject_mitm_proxy_advanced()  # Start proxy injection
        >>> # Run your app/tests here...
        >>> findings = scan_mitm("./mitm_traffic.ndjson")
    """
    from pathlib import Path
    from .scanners import parse_mitm_traffic
    
    traffic_path = Path(traffic_file)
    
    # If start_proxy requested, initialize MITM injection
    if start_proxy:
        print(f"[MITM] Starting proxy on port {port}...")
        from .scanners.inject_mitm_proxy import inject_mitm_proxy_advanced
        import os
        os.environ["MITM_PROXY_PORT"] = str(port)
        inject_mitm_proxy_advanced()
        print(f"[MITM] Proxy active. HTTP clients will be auto-patched.")
        print(f"[MITM] Traffic logging to: {traffic_path}")
        print(f"[MITM] Run your app/tests, then call parse_mitm_traffic() to analyze")
        return {
            "status": "proxy_started",
            "port": port,
            "traffic_file": str(traffic_path),
            "message": "Proxy running. Exercise your app then parse traffic file."
        }
    
    # Otherwise just parse existing traffic file
    return parse_mitm_traffic(traffic_path)


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
    
    # Load config from file or use kwargs
    if config_file:
        config = load_config(config_file)
    else:
        config = {}
    
    # Apply kwargs overrides
    config.update(kwargs)
    
    results = {
        "git": [],
        "mitm": [],
        "web": [],
        "runtime": [],
    }
    
    # Extract scanner settings from nested structure or flat structure
    scanner_config = config.get("scanner", {})
    
    # Git scan
    git_config = scanner_config.get("git", {})
    git_enabled = git_config.get("enabled", config.get("enable_git", False))
    
    if git_enabled:
        from .scanners import scan_git_history
        from .exceptions import ScannerError
        try:
            root = git_config.get("root") or config.get("root", ".")
            max_commits = git_config.get("max_commits") or config.get("max_commits", 50)
            results["git"] = scan_git_history(root, max_commits=max_commits)
        except Exception as e:
            raise ScannerError(f"Git scan failed: {e}")
    
    # MITM scan (before web scan - captures traffic from web scan if proxy is active)
    mitm_config = scanner_config.get("mitm", {})
    mitm_enabled = mitm_config.get("enabled", config.get("enable_mitm", False))
    
    if mitm_enabled:
        print(f"  [mitm] Starting MITM workflow...")
        traffic_file = mitm_config.get("traffic_file") or config.get("mitm_traffic")
        inject_proxy = mitm_config.get("inject_proxy", config.get("inject_proxy", True))
        proxy_port = mitm_config.get("port", config.get("mitm_port", 8082))
        
        if traffic_file:
            from pathlib import Path
            from .scanners import parse_mitm_traffic
            
            traffic_path = Path(traffic_file)
            
            # Initialize MITM proxy injection if requested
            if inject_proxy:
                print(f"  [mitm] Injecting proxy on port {proxy_port}...")
                try:
                    from .scanners.inject_mitm_proxy import inject_mitm_proxy_advanced
                    import os
                    os.environ["MITM_PROXY_PORT"] = str(proxy_port)
                    inject_mitm_proxy_advanced()
                    print(f"  [mitm] ✓ Proxy active, HTTP clients patched")
                    print(f"  [mitm] ✓ Traffic logging to: {traffic_path}")
                except Exception as e:
                    print(f"  [mitm] ✗ Proxy injection failed: {e}")
            
            try:
                # Parse traffic file (may be empty if proxy just started)
                if traffic_path.exists() and traffic_path.stat().st_size > 0:
                    result = parse_mitm_traffic(traffic_path)
                    
                    # Combine traffic findings and security findings
                    all_mitm_findings = result["security_findings"] + result["traffic_findings"]
                    results["mitm"] = all_mitm_findings
                    
                    print(f"  [mitm] Processed {result['proxied']} proxied requests, {result['bypassed']} bypassed")
                    print(f"  [mitm] Found {len(result['security_findings'])} security issues")
                else:
                    print(f"  [mitm] Traffic file empty or not found (may need to run app first)")
                    results["mitm"] = []
            except Exception as e:
                print(f"  [mitm] ✗ Error parsing traffic: {e}")
        else:
            print(f"  [mitm] Skipped - no traffic file specified")
    
    # Web scan
    web_config = scanner_config.get("web", {})
    web_enabled = web_config.get("enabled", config.get("enable_web", False))
    
    if web_enabled:
        from .exceptions import ScannerError
        try:
            target = web_config.get("target") or config.get("target")
            if target:
                print(f"  [web] Starting scan of {target}...")
                max_pages = web_config.get("max_pages") or config.get("max_pages", 50)
                results["web"] = scan_web(target, max_pages=max_pages)
                print(f"  [web] Found {len(results['web'])} issues")
            else:
                print(f"  [web] Skipped - no target specified")
        except Exception as e:
            print(f"  [web] ✗ Error: {e}")
            # Don't raise - continue with other scanners
    
    # Runtime scan
    runtime_config = scanner_config.get("runtime", {})
    runtime_enabled = runtime_config.get("enabled", config.get("enable_runtime", False))
    
    if runtime_enabled:
        print(f"  [runtime] Runtime scanner not yet implemented")
        # TODO: Implement runtime scanner
        # This would analyze running processes, open ports, loaded libraries, etc.
    
    return results
