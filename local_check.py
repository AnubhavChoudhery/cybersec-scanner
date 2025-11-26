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
    from scanners.browser_scanner import playwright_inspect, process_browser_findings
except Exception:
    def playwright_inspect(*args, **kwargs):
        return {"error": "playwright not installed"}
    def process_browser_findings(*args, **kwargs):
        return []

try:
    from scanners.web_crawler import LocalCrawler, process_crawler_findings
except Exception:
    LocalCrawler = None
    def process_crawler_findings(*args, **kwargs):
        return []

# NEW UPDATED IMPORTS
try:
    from scanners.network_scanner import run_mitm_dump, stop_mitm_dump
    from scanners.mitm_processor import parse_mitm_traffic
except Exception:
    def run_mitm_dump(*a, **k): return (None, "mitmproxy missing")
    def stop_mitm_dump(*a, **k): return {"error": "mitmproxy missing"}
    def parse_mitm_traffic(*a, **k): return {"traffic_findings": [], "proxied": 0, "bypassed": 0, "security_findings": []}

# RAG Pipeline imports
try:
    from rag.knowledge_graph import KnowledgeGraph
    from rag.retriever import Retriever
    from rag.llm_client import generate_answer
    from database.normalizer import DatabaseNormalizer
    RAG_AVAILABLE = True
except Exception as e:
    RAG_AVAILABLE = False
    print(f"[WARN] RAG pipeline unavailable: {e}")

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
    parser.add_argument("--enable-runtime", action="store_true", help="Enable runtime inspection (browser + web crawler)")
    parser.add_argument("--enable-mitm", action="store_true", help="Enable MITM Network Inspection")

    parser.add_argument("--max-commits", type=int, default=50, help="Max commits to scan in git history")
    parser.add_argument("--mitm-traffic", required=True, help="Path to mitm traffic NDJSON file (will be cleared at start)")
    
    # RAG Pipeline options
    parser.add_argument("--enable-rag", action="store_true", help="Enable RAG pipeline (Knowledge Graph + LLM analysis)")
    parser.add_argument("--rag-db", default="security_audit.db", help="SQLite database path for RAG")
    parser.add_argument("--llm-model", default="gemma3:1b", help="Ollama model for LLM analysis")

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

                # Parse traffic NDJSON file
                traffic_data = parse_mitm_traffic(TRAFFIC_FILE)
                
                all_findings.extend(traffic_data["traffic_findings"])
                all_findings.extend(traffic_data["security_findings"])
                stats["mitm_proxied"] = traffic_data["proxied"]
                stats["mitm_bypassed"] = traffic_data["bypassed"]
                stats["mitm_security_findings"] = len(traffic_data["security_findings"])
                
                print(f"{Fore.GREEN}[OK] Injector traffic parsed{Style.RESET_ALL}")
                print(f"Proxied (injector): {traffic_data['proxied']}")
                print(f"Bypassed (injector): {traffic_data['bypassed']}")
                
                if traffic_data["security_findings"]:
                    print(f"{Fore.RED}[!] Security issues found: {len(traffic_data['security_findings'])}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[OK] No security issues detected{Style.RESET_ALL}")

                # Report mitmproxy addon results if available
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
    # PHASE 3: RUNTIME INSPECTION (Browser + Web Crawler)
    # ==========================================================================
    if args.enable_runtime:
        print(f"{Fore.GREEN}[PHASE 3] Runtime Inspection (Browser + Web Crawler){Style.RESET_ALL}")
        
        # Browser Runtime Checks
        print(f"{Fore.CYAN}  → Browser Runtime Checks{Style.RESET_ALL}")
        try:
            br = playwright_inspect(args.target)
            if "error" in br:
                print(f"{Fore.YELLOW}[WARN] Browser unavailable: {br['error']}{Style.RESET_ALL}")
            else:
                browser_findings = process_browser_findings(br)
                stats["browser_issues"] = len(browser_findings)
                all_findings.extend(browser_findings)

                if browser_findings:
                    print(f"{Fore.YELLOW}[!] {len(browser_findings)} browser issues detected{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[OK] No browser issues{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[ERROR] Browser scan failed: {e}{Style.RESET_ALL}")
        
        # Web Crawler (Full JS Scanning)
        if LocalCrawler:
            print(f"{Fore.CYAN}  → Web Crawler (Full JS Scanning){Style.RESET_ALL}")
            try:
                crawler = LocalCrawler(args.target, max_pages=100, max_js_size=None)
                crawler.crawl()

                crawler_findings = process_crawler_findings(crawler.findings)
                stats["crawler_issues"] = len(crawler_findings)
                all_findings.extend(crawler_findings)

                print(f"{Fore.CYAN}[OK] Crawled {len(crawler.visited)} pages{Style.RESET_ALL}")
                if crawler_findings:
                    print(f"{Fore.YELLOW}[!] {len(crawler_findings)} issues found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[OK] No crawler issues{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[ERROR] Crawler failed: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[WARN] Web crawler unavailable (requests library missing){Style.RESET_ALL}")
        
        print()

    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 3] Runtime Inspection - SKIPPED{Style.RESET_ALL}\n")

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

    # ==========================================================================
    # PHASE 4: RAG PIPELINE (Knowledge Graph + LLM Analysis)
    # ==========================================================================
    if args.enable_rag and RAG_AVAILABLE:
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[PHASE 4] RAG Pipeline - Knowledge Graph + LLM Analysis{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        try:
            # Step 1: Build Knowledge Graph
            print(f"{Fore.CYAN}  → Building Knowledge Graph from findings...{Style.RESET_ALL}")
            kg = KnowledgeGraph()
            kg.build_from_audit(Path("audit_report.json"))
            
            graph_path = Path("rag/graph.gpickle")
            kg.save(graph_path)
            
            graph_stats = kg.stats()
            print(f"{Fore.GREEN}[OK] Knowledge Graph built successfully{Style.RESET_ALL}")
            print(f"    Findings: {graph_stats['findings']}")
            print(f"    Endpoints: {graph_stats['endpoints']}")
            print(f"    CWE Classifications: {graph_stats['cwes']}")
            print(f"    OWASP Mappings: {graph_stats['owasps']}")
            print(f"    Mitigations: {graph_stats['mitigations']}")
            print(f"    Attack Vectors: {graph_stats['attack_vectors']}")
            print(f"    Code Examples: {graph_stats['code_examples']}")
            print(f"    Total Edges: {graph_stats['edges']}")
            print()
            
            # Step 2: Normalize to SQLite Database
            print(f"{Fore.CYAN}  → Normalizing to SQLite database...{Style.RESET_ALL}")
            db_path = args.rag_db
            normalizer = DatabaseNormalizer(db_path)
            norm_stats = normalizer.normalize_from_graph(kg)
            
            print(f"{Fore.GREEN}[OK] Database normalized{Style.RESET_ALL}")
            print(f"    Findings stored: {norm_stats['findings']}")
            print(f"    Endpoints stored: {norm_stats['endpoints']}")
            print(f"    CWEs stored: {norm_stats['cwes']}")
            print()
            
            # Step 3: Generate Comprehensive LLM Analysis
            if all_findings:
                print(f"{Fore.CYAN}  → Generating comprehensive LLM analysis...{Style.RESET_ALL}")
                
                # Create retriever
                retriever = Retriever(graph_path=graph_path)
                
                try:
                    # Analysis 1: Executive Summary
                    print(f"{Fore.CYAN}    • Executive Summary{Style.RESET_ALL}")
                    all_contexts = retriever.retrieve("all security findings vulnerabilities issues", k=10)
                    
                    if all_contexts:
                        exec_query = f"Provide an executive summary of all {len(all_findings)} security findings. Include: 1) Overall security posture, 2) Most critical issues, 3) Priority recommendations."
                        exec_result = generate_answer(exec_query, all_contexts, model=args.llm_model, timeout=60)
                        exec_summary = exec_result.get("text", "Summary generation failed")
                    else:
                        exec_summary = "No findings available for analysis."
                    
                    # Analysis 2: Severity Breakdown
                    print(f"{Fore.CYAN}    • Severity Analysis{Style.RESET_ALL}")
                    severity_query = "Analyze the severity distribution of findings. Explain why each HIGH/CRITICAL issue is dangerous and what could be exploited."
                    severity_result = generate_answer(severity_query, all_contexts[:8], model=args.llm_model, timeout=60)
                    severity_analysis = severity_result.get("text", "Analysis unavailable")
                    
                    # Analysis 3: Remediation Plan
                    print(f"{Fore.CYAN}    • Remediation Roadmap{Style.RESET_ALL}")
                    remediation_query = "Create a prioritized remediation roadmap. For each issue type, provide: 1) Fix complexity (Easy/Medium/Hard), 2) Step-by-step mitigation, 3) Code examples where applicable."
                    remediation_result = generate_answer(remediation_query, all_contexts[:8], model=args.llm_model, timeout=90)
                    remediation_plan = remediation_result.get("text", "Remediation plan unavailable")
                    
                    # Analysis 4: OWASP/CWE Mapping
                    print(f"{Fore.CYAN}    • Compliance Analysis{Style.RESET_ALL}")
                    compliance_query = "Map these findings to OWASP Top 10 and CWE categories. Explain compliance implications and industry standards violated."
                    compliance_result = generate_answer(compliance_query, all_contexts[:6], model=args.llm_model, timeout=60)
                    compliance_analysis = compliance_result.get("text", "Compliance analysis unavailable")
                    
                    # Display comprehensive results
                    print(f"\n{Fore.GREEN}[OK] LLM Analysis Complete{Style.RESET_ALL}")
                    print(f"\n{Fore.YELLOW}{'='*70}")
                    print("COMPREHENSIVE SECURITY ANALYSIS (LLM-Generated)")
                    print(f"{'='*70}{Style.RESET_ALL}\n")
                    
                    print(f"{Fore.CYAN}━━━ EXECUTIVE SUMMARY ━━━{Style.RESET_ALL}\n")
                    print(exec_summary)
                    
                    print(f"\n{Fore.CYAN}━━━ SEVERITY ANALYSIS ━━━{Style.RESET_ALL}\n")
                    print(severity_analysis)
                    
                    print(f"\n{Fore.CYAN}━━━ REMEDIATION ROADMAP ━━━{Style.RESET_ALL}\n")
                    print(remediation_plan)
                    
                    print(f"\n{Fore.CYAN}━━━ COMPLIANCE ANALYSIS (OWASP/CWE) ━━━{Style.RESET_ALL}\n")
                    print(compliance_analysis)
                    
                    print(f"\n{Fore.YELLOW}{'='*70}{Style.RESET_ALL}\n")
                    
                    # Save comprehensive analysis to file
                    with open("rag_analysis.txt", "w", encoding="utf-8") as f:
                        f.write("═" * 80 + "\n")
                        f.write("  COMPREHENSIVE SECURITY ANALYSIS - LLM GENERATED\n")
                        f.write("═" * 80 + "\n")
                        f.write(f"Scan Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Findings: {len(all_findings)}\n")
                        f.write(f"LLM Model:      {args.llm_model}\n")
                        f.write("═" * 80 + "\n\n")
                        
                        f.write("\n" + "━" * 80 + "\n")
                        f.write("  EXECUTIVE SUMMARY\n")
                        f.write("━" * 80 + "\n\n")
                        # Add line breaks for better readability
                        formatted_exec = exec_summary.replace(". ", ".\n\n").replace(":\n", ":\n\n")
                        f.write(formatted_exec + "\n\n")
                        
                        f.write("\n" + "━" * 80 + "\n")
                        f.write("  SEVERITY ANALYSIS\n")
                        f.write("━" * 80 + "\n\n")
                        formatted_severity = severity_analysis.replace(". ", ".\n\n").replace(":\n", ":\n\n")
                        f.write(formatted_severity + "\n\n")
                        
                        f.write("\n" + "━" * 80 + "\n")
                        f.write("  REMEDIATION ROADMAP\n")
                        f.write("━" * 80 + "\n\n")
                        formatted_remediation = remediation_plan.replace(". ", ".\n\n").replace(":\n", ":\n\n")
                        f.write(formatted_remediation + "\n\n")
                        
                        f.write("\n" + "━" * 80 + "\n")
                        f.write("  COMPLIANCE ANALYSIS (OWASP/CWE)\n")
                        f.write("━" * 80 + "\n\n")
                        formatted_compliance = compliance_analysis.replace(". ", ".\n\n").replace(":\n", ":\n\n")
                        f.write(formatted_compliance + "\n\n")
                        
                        f.write("\n" + "═" * 80 + "\n")
                        f.write("  END OF ANALYSIS\n")
                        f.write("═" * 80 + "\n")
                    
                    print(f"{Fore.GREEN}[OK] Comprehensive analysis saved to rag_analysis.txt{Style.RESET_ALL}\n")
                    
                    # Also create a quick summary file
                    with open("rag_summary.txt", "w", encoding="utf-8") as f:
                        f.write("═" * 80 + "\n")
                        f.write("  SECURITY AUDIT - EXECUTIVE SUMMARY\n")
                        f.write("═" * 80 + "\n\n")
                        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Findings:  {len(all_findings)} total\n")
                        f.write(f"Model:     {args.llm_model}\n\n")
                        f.write("─" * 80 + "\n\n")
                        # Format with line breaks
                        formatted_summary = exec_summary.replace(". ", ".\n\n").replace(":\n", ":\n\n")
                        f.write(formatted_summary)
                        f.write("\n\n" + "═" * 80 + "\n")
                        f.write(f">> For complete analysis with remediation steps, see: rag_analysis.txt\n")
                        f.write("═" * 80 + "\n")
                    
                except Exception as e:
                    print(f"{Fore.YELLOW}[WARN] LLM analysis failed: {e}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}      Make sure Ollama is running: ollama serve{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}      And model is available: ollama pull {args.llm_model}{Style.RESET_ALL}\n")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"{Fore.GREEN}[OK] No findings to analyze{Style.RESET_ALL}\n")
            
            # Step 4: Provide interactive query instructions
            print(f"{Fore.CYAN}{'='*70}")
            print("RAG ANALYSIS FILES GENERATED")
            print(f"{'='*70}{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[+] audit_report.json{Style.RESET_ALL}     - Raw scanner findings (JSON)")
            print(f"{Fore.GREEN}[+] rag/graph.gpickle{Style.RESET_ALL}     - Knowledge graph (NetworkX)")
            print(f"{Fore.GREEN}[+] security_audit.db{Style.RESET_ALL}     - SQLite database (queryable)")
            print(f"{Fore.GREEN}[+] rag_summary.txt{Style.RESET_ALL}       - Quick executive summary")
            print(f"{Fore.GREEN}[+] rag_analysis.txt{Style.RESET_ALL}      - Full LLM analysis (recommended)")
            
            print(f"\n{Fore.CYAN}{'='*70}")
            print("INTERACTIVE QUERIES (Optional)")
            print(f"{'='*70}{Style.RESET_ALL}")
            print(f"\n{Fore.LIGHTBLACK_EX}For ad-hoc questions, use:{Style.RESET_ALL}\n")
            print(f"  python rag/cli.py --query \"What are the API key exposures?\"")
            print(f"  python rag/cli.py --query \"Show me authentication vulnerabilities\"")
            print(f"  sqlite3 {db_path} \"SELECT severity, summary FROM findings;\"")
            print()
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] RAG pipeline failed: {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        
    elif args.enable_rag and not RAG_AVAILABLE:
        print(f"{Fore.YELLOW}[WARN] RAG pipeline requested but dependencies missing{Style.RESET_ALL}")
        print(f"       Install: pip install networkx ollama pytest{Style.RESET_ALL}\n")
    
    else:
        print(f"{Fore.LIGHTBLACK_EX}[PHASE 4] RAG Pipeline - SKIPPED{Style.RESET_ALL}")
        print(f"         Enable with: --enable-rag{Style.RESET_ALL}\n")

    # Exit codes
    if severities["CRITICAL"] > 0:
        sys.exit(2)
    if severities["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
