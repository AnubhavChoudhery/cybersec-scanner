"""
Security scanner modules for runtime and version control analysis.

Provides scanners for:
- Git history (committed secrets)
- Web crawling (HTTP responses, JavaScript, source maps)
- Browser runtime (Playwright - localStorage, cookies, etc.)
- MITM HTTPS inspection (mitmproxy-based traffic analysis)
"""

from .git_scanner import scan_git_history
from .web_crawler import LocalCrawler
from .browser_scanner import playwright_inspect
from .network_scanner import (
    run_mitm_proxy_background,
    stop_mitm_proxy,
    print_mitm_instructions,
    get_proxied_session
)

__all__ = [
    'scan_git_history',
    'LocalCrawler',
    'playwright_inspect',
    'run_mitm_proxy_background',
    'stop_mitm_proxy',
    'print_mitm_instructions',
    'get_proxied_session',
]
