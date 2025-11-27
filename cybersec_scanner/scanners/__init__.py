"""
Security scanner modules for runtime and version control analysis.

Provides scanners for:
- Git history (committed secrets)
- Web crawling (HTTP responses, JavaScript, source maps)
- Browser runtime (Playwright - localStorage, cookies, etc.)
- MITM HTTPS inspection (mitmproxy-based traffic analysis)
"""

from .git_scanner import scan_git_history
from .web_crawler import LocalCrawler, process_crawler_findings
from .browser_scanner import playwright_inspect, process_browser_findings
from .network_scanner import run_mitm_dump, stop_mitm_dump
from .mitm_processor import parse_mitm_traffic
from .inject_mitm_proxy import (
    inject_mitm_proxy_advanced,
    DEFAULT_TRAFFIC_FILE,
    CYBERSEC_TEMP_DIR,
)

__all__ = [
    'scan_git_history',
    'LocalCrawler',
    'process_crawler_findings',
    'playwright_inspect',
    'process_browser_findings',
    'run_mitm_dump',
    'stop_mitm_dump',
    'parse_mitm_traffic',
    'inject_mitm_proxy_advanced',
    'DEFAULT_TRAFFIC_FILE',
    'CYBERSEC_TEMP_DIR',
]
