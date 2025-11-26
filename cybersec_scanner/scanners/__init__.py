"""
Security scanners for different data sources.

This module provides individual scanners that can be used independently:
- GitScanner: Scan git history for secrets and vulnerabilities
- WebCrawler: Crawl and analyze web applications
- BrowserScanner: Analyze browser extension security
- NetworkScanner: Intercept and analyze network traffic (MITM)
"""

from .git_scanner import scan_git_history
from .web_crawler import LocalCrawler, process_crawler_findings
from .network_scanner import run_mitm_dump, stop_mitm_dump

__all__ = [
    "scan_git_history",
    "LocalCrawler",
    "process_crawler_findings",
    "run_mitm_dump",
    "stop_mitm_dump",
]
