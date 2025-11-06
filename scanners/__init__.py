"""
Security scanner modules.

This package contains specialized scanners for different attack surfaces:
- static_scanner: File-based secret detection
- git_scanner: Git history analysis
- web_crawler: HTTP endpoint scanning
- browser_scanner: Runtime browser inspection (Playwright)
- network_scanner: Packet capture analysis
"""

from .static_scanner import scan_files
from .git_scanner import scan_git_history
from .web_crawler import LocalCrawler
from .browser_scanner import playwright_inspect
from .network_scanner import run_packet_capture, pcap_capture_results

__all__ = [
    'scan_files',
    'scan_git_history',
    'LocalCrawler',
    'playwright_inspect',
    'run_packet_capture',
    'pcap_capture_results',
]
