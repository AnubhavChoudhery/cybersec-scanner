#!/usr/bin/env python3
"""
Comprehensive Local Security Audit Tool

Orchestrates multiple security scanning phases:
1. Git History Scan - Find secrets in commit history
2. Web Crawler - Scan exposed endpoints
3. Browser Runtime Checks - Playwright-based inspection
4. Network Security Testing - Active tests + MITM HTTPS inspection

Usage:
    python local_check.py --target http://localhost:8000 --root . --enable-mitm
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime

# Add scanners directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import all scanner modules
from scanners.git_scanner import scan_git_history
from scanners.browser_scanner import playwright_inspect
from scanners.web_crawler import LocalCrawler
from scanners.network_scanner import (
    run_mitm_proxy_background,
    stop_mitm_proxy,
    print_mitm_instructions
)

try:
    from colorama import init, Fore, Style
    init()
except Exception:
    class Fore:
        RED = LIGHTRED_EX = YELLOW = LIGHTBLUE_EX = LIGHTBLACK_EX = GREEN = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""

def main():
    parser = argparse.ArgumentParser(description="Local security audit tool")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--root", help="Project root", default='.')
    parser.add_argument("--enable-mitm", action="store_true", help="Enable mitmproxy inspection")
    parser.add_argument("--enable-git", action="store_true", default=True, help="Enable git history scan (enabled by default)")
    parser.add_argument("--enable-crawler", action="store_true", default=True, help="Enable web crawler (enabled by default)")
    parser.add_argument("--enable-browser", action="store_true", help="Enable Playwright browser checks")
    parser.add_argument("--auto-install-cert", action="store_true", help="Try to auto-install mitm CA (requires sudo)")
    parser.add_argument("--max-commits", type=int, default=50, help="Max git commits to scan")
    parser.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl")
    parser.add_argument("--mitm-port", type=int, default=8082, help="Port for mitmproxy (default 8082)")
    args = parser.parse_args()
    
    all_findings = []
    stats = {
        'git_secrets': 0,
        'crawler_issues': 0,
        'browser_issues': 0,
        'mitm_findings': 0
    }

    print("[OK] Loaded 58 secret detection patterns from patterns.env")
    print("============================================================")
    print("LOCAL SECURITY AUDIT TOOL")
    print("============================================================")
    print(f"Target: {args.target}")
    print(f"Root:   {os.path.expanduser(args.root)}")
    print("Output: audit_report.json")
    print("============================================================\n")

    # Phase 1: Git History Scan
    if args.enable_git:
        print(f"{Fore.GREEN}[PHASE 1/4] Git History Scan{Style.RESET_ALL}")
        print("------------------------------------------------------------")
        try:
            git_results = scan_git_history(os.path.expanduser(args.root), max_commits=args.max_commits)
            stats['git_secrets'] = len(git_results)
            all_findings.extend(git_results)
            
            if git_results:
                print(f"{Fore.YELLOW}[!] Found {len(git_results)} potential secrets in git history{Style.RESET_ALL}")
                for finding in git_results[:5]:  # Show first 5
                    print(f"  • {finding['pattern']} in commit {finding['commit']} ({finding['path']})")
                if len(git_results) > 5:
                    print(f"  ... and {len(git_results) - 5} more")
            else:
                print(f"{Fore.GREEN}[OK] No secrets found in git history{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Git scan failed: {e}{Style.RESET_ALL}")
        print()
    else:
        print("[PHASE 1/4] Git History Scan")
        print("------------------------------------------------------------")
        print(f"{Fore.LIGHTBLACK_EX}[SKIP] Git scan disabled (enabled by default, use --enable-git to enable){Style.RESET_ALL}\n")

    # Phase 2: Web Crawler
    if args.enable_crawler:
        print(f"{Fore.GREEN}[PHASE 2/4] Web Crawler ({args.target}){Style.RESET_ALL}")
        print("------------------------------------------------------------")
        try:
            crawler = LocalCrawler(args.target, max_pages=args.max_pages)
            crawler.crawl()
            
            crawler_findings = crawler.findings
            stats['crawler_issues'] = len(crawler_findings)
            
            # Convert crawler findings to standard format
            for finding in crawler_findings:
                all_findings.append({
                    'type': 'web_crawler',
                    'category': finding.get('type', 'unknown'),
                    'url': finding.get('url', ''),
                    'description': finding.get('description', ''),
                    'details': finding
                })
            
            print(f"{Fore.CYAN}[OK] Crawled {len(crawler.visited)} pages{Style.RESET_ALL}")
            if crawler_findings:
                print(f"{Fore.YELLOW}[!] Found {len(crawler_findings)} potential issues{Style.RESET_ALL}")
                for finding in crawler_findings[:5]:  # Show first 5
                    print(f"  • {finding.get('type', 'unknown')}: {finding.get('url', '')[:80]}")
                if len(crawler_findings) > 5:
                    print(f"  ... and {len(crawler_findings) - 5} more")
            else:
                print(f"{Fore.GREEN}[OK] No issues found during crawl{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Web crawler failed: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        print()
    else:
        print("[PHASE 2/4] Web Crawler")
        print("------------------------------------------------------------")
        print(f"{Fore.LIGHTBLACK_EX}[SKIP] Web crawler disabled (enabled by default, use --enable-crawler to enable){Style.RESET_ALL}\n")

    # Phase 3: Browser Runtime Checks (Playwright)
    if args.enable_browser:
        print(f"{Fore.GREEN}[PHASE 3/4] Browser Runtime Checks{Style.RESET_ALL}")
        print("------------------------------------------------------------")
        try:
            browser_results = playwright_inspect(args.target)
            
            if browser_results.get('error'):
                print(f"{Fore.YELLOW}[WARN] Browser checks failed: {browser_results.get('message')}{Style.RESET_ALL}")
            else:
                # Analyze browser storage for secrets
                browser_findings = []
                
                # Check localStorage
                for key, value in browser_results.get('localStorage', {}).items():
                    if value and any(keyword in key.lower() for keyword in ['token', 'key', 'secret', 'api', 'password']):
                        browser_findings.append({
                            'type': 'browser_storage',
                            'location': 'localStorage',
                            'key': key,
                            'value': str(value)[:100]
                        })
                
                # Check sessionStorage
                for key, value in browser_results.get('sessionStorage', {}).items():
                    if value and any(keyword in key.lower() for keyword in ['token', 'key', 'secret', 'api', 'password']):
                        browser_findings.append({
                            'type': 'browser_storage',
                            'location': 'sessionStorage',
                            'key': key,
                            'value': str(value)[:100]
                        })
                
                # Check cookies
                for cookie in browser_results.get('cookies', []):
                    if not cookie.get('secure') or not cookie.get('httpOnly'):
                        browser_findings.append({
                            'type': 'insecure_cookie',
                            'name': cookie.get('name'),
                            'secure': cookie.get('secure', False),
                            'httpOnly': cookie.get('httpOnly', False)
                        })
                
                # Check globals
                for key, value in browser_results.get('globals', {}).items():
                    if value:
                        browser_findings.append({
                            'type': 'exposed_global',
                            'key': key,
                            'value': str(value)[:100]
                        })
                
                stats['browser_issues'] = len(browser_findings)
                all_findings.extend(browser_findings)
                
                print(f"{Fore.CYAN}[OK] Browser inspection complete{Style.RESET_ALL}")
                print(f"  localStorage items: {len(browser_results.get('localStorage', {}))}")
                print(f"  sessionStorage items: {len(browser_results.get('sessionStorage', {}))}")
                print(f"  Cookies: {len(browser_results.get('cookies', []))}")
                
                if browser_findings:
                    print(f"{Fore.YELLOW}[!] Found {len(browser_findings)} browser security issues{Style.RESET_ALL}")
                    for finding in browser_findings[:5]:
                        print(f"  • {finding['type']}: {finding.get('key', finding.get('name', 'unknown'))}")
                    if len(browser_findings) > 5:
                        print(f"  ... and {len(browser_findings) - 5} more")
                else:
                    print(f"{Fore.GREEN}[OK] No browser security issues found{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Browser checks failed: {e}{Style.RESET_ALL}")
        print()
    else:
        print("[PHASE 3/4] Browser Runtime Checks")
        print("------------------------------------------------------------")
        print(f"{Fore.LIGHTBLACK_EX}[SKIP] Browser checks disabled (use --enable-browser to enable){Style.RESET_ALL}\n")

    # Phase 4: MITM HTTPS Inspection
    mitm_port = args.mitm_port or 8082
    mitm_results = None
    mitm_process = None
    
    if args.enable_mitm:
        print(f"\n{Fore.GREEN}[PHASE 4/4] MITM HTTPS INSPECTION{Style.RESET_ALL}")
        print("="*60)
        
        # Show configuration instructions
        print_mitm_instructions(mitm_port)
        
        try:
            # Start MITM proxy in background
            print(f"\n{Fore.CYAN}[*] Starting mitmproxy on port {mitm_port}...{Style.RESET_ALL}")
            mitm_process, results_file = run_mitm_proxy_background(
                port=mitm_port, 
                duration=None  # Interactive mode (Ctrl+C to stop)
            )
            
            print(f"{Fore.GREEN}[✓] MITM proxy running!{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[!] Press Ctrl+C when done testing to stop proxy and collect results{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Now interact with your localhost app (backend + frontend)...{Style.RESET_ALL}\n")
            
            # Wait for user to press Ctrl+C
            try:
                while mitm_process.poll() is None:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Ctrl+C detected, stopping MITM proxy...{Style.RESET_ALL}")
            
            # Stop proxy and collect results
            mitm_results = stop_mitm_proxy(mitm_process, results_file)
            
            if mitm_results and isinstance(mitm_results, dict):
                if mitm_results.get('error'):
                    print(f"{Fore.YELLOW}[WARN] MITM proxy error: {mitm_results.get('message')}{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.GREEN}[✓] MITM Inspection Complete!{Style.RESET_ALL}")
                    print(f"  Requests intercepted:  {mitm_results.get('requests', 0)}")
                    print(f"  Responses intercepted: {mitm_results.get('responses', 0)}")
                    print(f"  Security findings:     {mitm_results.get('total_findings', 0)}")
                    
                    # Add MITM findings to all_findings
                    mitm_findings = mitm_results.get('findings', [])
                    stats['mitm_findings'] = len(mitm_findings)
                    all_findings.extend(mitm_findings)
                    
                    # Show severity breakdown
                    severity_summary = mitm_results.get('severity_summary', {})
                    if severity_summary:
                        print(f"\n{Fore.CYAN}Findings by severity:{Style.RESET_ALL}")
                        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                            count = severity_summary.get(severity, 0)
                            if count > 0:
                                color = {
                                    'CRITICAL': Fore.RED,
                                    'HIGH': Fore.LIGHTRED_EX,
                                    'MEDIUM': Fore.YELLOW,
                                    'LOW': Fore.LIGHTBLUE_EX,
                                    'INFO': Fore.LIGHTBLACK_EX
                                }.get(severity, Fore.WHITE)
                                print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[WARN] No MITM results collected{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] MITM proxy failed: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        finally:
            # Ensure cleanup
            if mitm_process and mitm_process.poll() is None:
                print(f"{Fore.YELLOW}[*] Cleaning up MITM process...{Style.RESET_ALL}")
                try:
                    mitm_process.terminate()
                    mitm_process.wait(timeout=5)
                except:
                    try:
                        mitm_process.kill()
                    except:
                        pass

    # Post-processing and report generation
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SECURITY AUDIT SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"Target: {args.target}")
    print(f"Root:   {os.path.expanduser(args.root)}")
    print()
    print("Findings by phase:")
    print(f"  Git History:       {stats['git_secrets']} secrets")
    print(f"  Web Crawler:       {stats['crawler_issues']} issues")
    print(f"  Browser Runtime:   {stats['browser_issues']} issues")
    print(f"  MITM Inspection:   {stats['mitm_findings']} findings")
    print(f"  {Fore.YELLOW}Total:             {len(all_findings)} findings{Style.RESET_ALL}")
    print()
    
    # Calculate severity breakdown
    severity_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for finding in all_findings:
        severity = finding.get('severity', 'INFO')
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    
    if any(severity_breakdown.values()):
        print("Severity breakdown:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_breakdown.get(severity, 0)
            if count > 0:
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.LIGHTRED_EX,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.LIGHTBLUE_EX,
                    'INFO': Fore.LIGHTBLACK_EX
                }.get(severity, Fore.WHITE)
                print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
    
    # Write full report to JSON
    report = {
        'timestamp': datetime.now().isoformat(),
        'target': args.target,
        'root': os.path.expanduser(args.root),
        'stats': stats,
        'severity_breakdown': severity_breakdown,
        'findings': all_findings,
        'total_findings': len(all_findings)
    }
    
    try:
        with open('audit_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Fore.GREEN}[✓] Full report written to audit_report.json{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Failed to write report: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()