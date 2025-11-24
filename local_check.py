#!/usr/bin/env python3
"""
Comprehensive Local Security Audit Tool (Aligned with updated MITM system)

Pipeline:
1. Git History Scan
2. Web Crawler
3. Browser Runtime Security Scan
4. MITM HTTPS Network Inspection (via network_scanner.run_mitm_dump)

This edition matches:
- your updated network_scanner.py (run_mitm_dump + stop_mitm_dump)
- your updated inject_mitm_proxy.py
- smart OAuth/AI bypass handled exclusively by injector
"""

import os
import sys
import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
try:
    from scanners.git_scanner import scan_git_history
except Exception:
    def scan_git_history(*args, **kwargs):
        return []

try:
    from scanners.browser_scanner import playwright_inspect
except Exception:
    def playwright_inspect(*args, **kwargs):
        return {"error": "playwright not installed"}

try:
    from scanners.web_crawler import LocalCrawler
except Exception:
    LocalCrawler = None

# NEW UPDATED IMPORTS (aligned with your rewritten system)
try:
    from scanners.network_scanner import run_mitm_dump, stop_mitm_dump
except Exception:
    def run_mitm_dump(*a, **k): return (None, "mitmproxy missing")
    def stop_mitm_dump(*a, **k): return {"error": "mitmproxy missing"}

# Colorama soft fallback
try:
    from colorama import init, Fore, Style
    init()
except Exception:
    class Fore:
        RED = LIGHTRED_EX = YELLOW = LIGHTBLUE_EX = LIGHTBLACK_EX = GREEN = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""

# ====================================================================
# MAIN
# ====================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Local Security Audit (Git, Crawl, Browser, MITM)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--target", help="http://localhost:8000")
    parser.add_argument("--root", default=".", help="Project root path")

    parser.add_argument("--enable-git", action="store_true", help="Enable git scanning")
    parser.add_argument("--enable-crawler", action="store_true", help="Enable crawler")
    parser.add_argument("--enable-browser", action="store_true", help="Enable browser inspection")
    parser.add_argument("--enable-mitm", action="store_true", help="Enable MITM Network Inspection")

    parser.add_argument("--max-commits", type=int, default=50, help="Max commits to scan in git history")
    parser.add_argument("--mitm-traffic", required=True, help="Path to mitm traffic NDJSON file (will be cleared at start)")

    args = parser.parse_args()

    # Use user-specified traffic file path
    TRAFFIC_FILE = Path(args.mitm_traffic)
    print(f"Using MITM traffic file: {TRAFFIC_FILE}")
    
    # Clear traffic file from previous runs (truncate to prevent data carryover)
    try:
        TRAFFIC_FILE.parent.mkdir(parents=True, exist_ok=True)
        TRAFFIC_FILE.write_text("")  # Truncate file
        print(f"{Fore.GREEN}[OK] Cleared traffic file for fresh run{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] Could not clear traffic file: {e}{Style.RESET_ALL}")

    all_findings = []
    stats = {
        "git_secrets": 0,
        "crawler_issues": 0,
        "browser_issues": 0,
        "mitm_findings": 0
    }

    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}LOCAL SECURITY AUDIT TOOL - UPDATED FOR MITM SYSTEM{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    print(f"Target: {args.target}")
    print(f"Root:   {os.path.abspath(args.root)}")
    print()

    # ==========================================================================
    # PHASE 1: GIT HISTORY SCAN (doesn't require running app)
    # ==========================================================================
    if args.enable_git:
        print(f"{Fore.GREEN}[PHASE 1] Git History Scan{Style.RESET_ALL}")
        try:
            results = scan_git_history(args.root, max_commits=args.max_commits)
            stats["git_secrets"] = len(results)
            all_findings.extend(results)

            if results:
                print(f"{Fore.YELLOW}[!] Found {len(results)} possible secrets{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[OK] No leaks found{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Git scan failed: {e}{Style.RESET_ALL}")
        print()

    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 1] Git Scan - SKIPPED{Style.RESET_ALL}\n")

    # ==========================================================================
    # PHASE 2: MITM INSPECTION (STARTS YOUR APP - must run before browser/crawler)
    # ==========================================================================
    mitm_results = None

    if args.enable_mitm:
        print(f"{Fore.GREEN}[PHASE 2] MITM HTTPS Network Inspection{Style.RESET_ALL}")
        print(f"Note: This will start your backend app. MITM proxy uses inject_mitm_proxy.py")
        print(f"      (port from MITM_PROXY_PORT env or 8082)")
        print(f"{Fore.CYAN}[ACTION REQUIRED] Start your backend app now, then press Ctrl+C when done testing{Style.RESET_ALL}\n")

        try:
            # Start standalone mitmproxy addon (for additional traffic capture)
            proc, results_path = run_mitm_dump(
                port=8082,  # Default port
                duration=None  # Interactive mode (Ctrl+C to stop)
            )

            if proc is None:
                print(f"{Fore.RED}[ERROR] MITM failed to launch: {results_path}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] MITM running — exercise your app then press Ctrl+C{Style.RESET_ALL}")
                try:
                    while proc.poll() is None:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print(f"{Fore.YELLOW}Stopping MITM...{Style.RESET_ALL}")

                mitm_results = stop_mitm_dump(proc, results_path)

                # Parse injector traffic NDJSON regardless of mitmproxy results
                # This ensures we capture traffic even if mitmproxy addon failed
                try:
                    proxied = 0
                    bypassed = 0
                    traffic_findings = []
                    
                    if TRAFFIC_FILE.exists():
                        with TRAFFIC_FILE.open("r", encoding="utf-8") as tf:
                                for line in tf:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    try:
                                        entry = json.loads(line)
                                        stage = entry.get("stage")
                                        
                                        # Flat structure: client/method/url are at top level
                                        client = entry.get("client")
                                        method = entry.get("method")
                                        url = entry.get("url")
                                        
                                        if stage == "mitm_outbound":
                                            proxied += 1
                                            # Add to findings for audit report
                                            traffic_findings.append({
                                                "type": "mitm_proxied_request",
                                                "severity": "INFO",
                                                "timestamp": entry.get("ts"),
                                                "timestamp_human": entry.get("timestamp"),
                                                "client": client,
                                                "method": method,
                                                "url": url,
                                                "description": f"Proxied request via MITM: {method} {url} (client={client})"
                                            })
                                        elif stage == "mitm_bypass":
                                            bypassed += 1
                                    except json.JSONDecodeError:
                                        continue
                    
                    # Add traffic findings to all_findings
                    all_findings.extend(traffic_findings)
                    stats["mitm_proxied"] = proxied
                    stats["mitm_bypassed"] = bypassed
                    
                    print(f"{Fore.GREEN}[OK] Injector traffic parsed{Style.RESET_ALL}")
                    print(f"Proxied (injector): {proxied}")
                    print(f"Bypassed (injector): {bypassed}")
                    
                    # Parse security findings from same file (stage=security_finding)
                    security_count = 0
                    if TRAFFIC_FILE.exists():
                        with TRAFFIC_FILE.open("r", encoding="utf-8") as tf:
                            for line in tf:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    if entry.get("stage") == "security_finding":
                                        # Add to all_findings with proper structure
                                        all_findings.append({
                                            "type": entry.get("type"),
                                            "severity": entry.get("severity"),
                                            "timestamp": entry.get("ts"),
                                            "timestamp_human": entry.get("timestamp"),
                                            "description": entry.get("description"),
                                            "url": entry.get("url"),
                                            "client": entry.get("client"),
                                            "method": entry.get("method"),
                                            "pattern": entry.get("pattern"),
                                            "field": entry.get("field"),
                                            "header": entry.get("header"),
                                        })
                                        security_count += 1
                                except json.JSONDecodeError:
                                    continue
                    
                    stats["mitm_security_findings"] = security_count
                    if security_count > 0:
                        print(f"{Fore.RED}[!] Security issues found: {security_count}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[OK] No security issues detected{Style.RESET_ALL}")
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[WARN] Traffic log parse error: {e}{Style.RESET_ALL}")

                # Now report mitmproxy addon results if available
                if isinstance(mitm_results, dict) and "error" not in mitm_results:
                    stats["mitm_findings"] = len(mitm_results.get("findings", []))
                    all_findings.extend(mitm_results.get("findings", []))

                    print(f"{Fore.GREEN}[OK] MITM addon complete{Style.RESET_ALL}")
                    print(f"Requests: {mitm_results.get('requests', 0)}")
                    print(f"Responses: {mitm_results.get('responses', 0)}")
                else:
                    print(f"{Fore.YELLOW}[WARN] MITM addon produced no results (traffic injector still captured above){Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] MITM failed: {e}{Style.RESET_ALL}")
        print()

    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 2] MITM - SKIPPED{Style.RESET_ALL}\n")

    # ==========================================================================
    # PHASE 3: BROWSER RUNTIME (requires running app)
    # ==========================================================================
    if args.enable_browser:
        print(f"{Fore.GREEN}[PHASE 3] Browser Runtime Checks{Style.RESET_ALL}")
        try:
            crawler = LocalCrawler(args.target, max_pages=100)  # Default max pages
            crawler.crawl()

            # Filter out non-issue findings (exclude successful status codes)
            real_issues = [
                f for f in crawler.findings 
                if f.get("type") != "status" or f.get("status", 200) >= 400
            ]
            
            stats["crawler_issues"] = len(real_issues)
            all_findings.extend([
                {
                    "type": "crawler_issue",
                    "url": f.get("url"),
                    "description": f.get("description"),
                    "details": f
                }
                for f in real_issues
            ])

            print(f"{Fore.CYAN}[OK] Crawled {len(crawler.visited)} pages{Style.RESET_ALL}")
            if real_issues:
                print(f"{Fore.YELLOW}[!] {len(real_issues)} issues found{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[OK] No crawler issues{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Browser scan failed: {e}{Style.RESET_ALL}")
        print()

    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 3] Browser - SKIPPED{Style.RESET_ALL}\n")

    # ==========================================================================
    # PHASE 4: WEB CRAWLER (requires running app, scans all JS files)
    # ==========================================================================
    if args.enable_crawler and LocalCrawler:
        print(f"{Fore.GREEN}[PHASE 4] Web Crawler (Full JS Scanning){Style.RESET_ALL}")
        try:
            br = playwright_inspect(args.target)
            if "error" in br:
                print(f"{Fore.YELLOW}[WARN] Browser unavailable: {br['error']}{Style.RESET_ALL}")
            else:
                findings = []

                # localStorage
                for k, v in br.get("localStorage", {}).items():
                    if any(t in k.lower() for t in ["token", "key", "secret", "api"]):
                        findings.append({
                            "type": "browser_storage",
                            "location": "localStorage",
                            "key": k,
                            "value": str(v)[:120]
                        })

                # sessionStorage
                for k, v in br.get("sessionStorage", {}).items():
                    if any(t in k.lower() for t in ["token", "key", "secret", "api"]):
                        findings.append({
                            "type": "browser_storage",
                            "location": "sessionStorage",
                            "key": k,
                            "value": str(v)[:120]
                        })

                # insecure cookies
                for c in br.get("cookies", []):
                    if not c.get("secure") or not c.get("httpOnly"):
                        findings.append({
                            "type": "cookie_insecure",
                            "name": c["name"],
                            "secure": c.get("secure"),
                            "httpOnly": c.get("httpOnly")
                        })

                # exposed globals
                for k, v in br.get("globals", {}).items():
                    if v not in (None, "", False):
                        findings.append({
                            "type": "browser_global",
                            "key": k,
                            "value": str(v)[:120]
                        })

                stats["browser_issues"] = len(findings)
                all_findings.extend(findings)

                if findings:
                    print(f"{Fore.YELLOW}[!] {len(findings)} browser issues detected{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[OK] No browser issues{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Crawler failed: {e}{Style.RESET_ALL}")
        print()

    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 4] Crawler - SKIPPED{Style.RESET_ALL}\n")

    # ==========================================================================
    # FINAL REPORT
    # ==========================================================================
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print("SEVERITY SUMMARY")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for f in all_findings:
        sev = f.get("severity", "INFO")
        severities[sev] = severities.get(sev, 0) + 1

    for s, c in severities.items():
        if c:
            color = {
                "CRITICAL": Fore.RED,
                "HIGH": Fore.LIGHTRED_EX,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.LIGHTBLUE_EX,
                "INFO": Fore.LIGHTBLACK_EX
            }.get(s, Fore.WHITE)
            print(f"  {color}{s}: {c}{Style.RESET_ALL}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "target": args.target,
        "stats": stats,
        "severities": severities,
        "findings": all_findings
    }

    with open("audit_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{Fore.GREEN}[OK] Full report saved to audit_report.json{Style.RESET_ALL}\n")

    # Exit codes
    if severities["CRITICAL"] > 0:
        sys.exit(2)
    if severities["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
