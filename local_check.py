"""
Comprehensive local security audit tool.

MAIN ENTRY POINT - Orchestrates all security scanners.

This tool performs multi-layered security analysis:
 - Static file scanning for hardcoded secrets
 - Git history analysis for committed secrets
 - HTTP crawling of localhost applications
 - JavaScript and source map analysis
 - Optional browser runtime inspection (Playwright)
 - Optional network packet capture (Scapy)

USAGE:
  python local_check.py --target http://localhost:8000 --root . --out audit_report.json

  Optional flags:
    --enable-playwright    Enable browser runtime checks
    --enable-pcap         Enable packet capture (requires admin/root)
    --depth N             Maximum pages to crawl (default: 300)

IMPORTANT:
 - Intended for lawful local testing only
 - Do not send raw secrets to cloud services
 - Rotate any discovered credentials immediately

Dependencies:
  Required: pip install requests
  Optional: pip install playwright scapy
           python -m playwright install   # for browser checks
"""
import os
import sys
import json
import time
import argparse
from collections import defaultdict

# Check for required dependencies
try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)

# Import configuration
from config import SCORE_THRESHOLD, KNOWN_PATTERNS

# Import utility functions
from utils import extract_string_literals, score_literal

# Import all scanners
from scanners import (
    scan_files,
    scan_git_history,
    LocalCrawler,
    playwright_inspect,
    run_packet_capture,
    pcap_capture_results
)


def main():
    """
    Main entry point for the local security audit tool.
    
    Orchestrates a comprehensive security scan by:
    1. Parsing command-line arguments
    2. Running static file analysis
    3. Scanning git history for leaked secrets
    4. Crawling the target localhost application
    5. Optionally running Playwright browser checks
    6. Optionally capturing network packets
    7. Deduplicating and summarizing findings
    8. Writing JSON report and printing summary
    
    Command-line Arguments:
        --target, -t: Target URL (default: http://localhost:8000)
        --root, -r: Repository root directory (default: .)
        --out, -o: Output JSON file (default: audit_report.json)
        --enable-playwright: Enable browser runtime checks
        --enable-pcap: Enable packet capture (requires admin/root)
        --pcap-timeout: Packet capture duration in seconds (default: 12)
        --depth: Maximum pages to crawl (default: 300)
        
    Output:
        - JSON file with all findings and metadata
        - Console summary showing high-confidence findings
        
    Exit Codes:
        0: Successful execution (findings may or may not exist)
        1: Fatal error (missing dependencies, invalid arguments)
        
    Example Usage:
        # Basic scan
        python local_check.py --target http://localhost:3000 --root ./myapp
        
        # Full scan with all features
        python local_check.py -t http://localhost:8000 -r . --enable-playwright --enable-pcap
        
        # Quick scan with limited depth
        python local_check.py -t http://localhost:5000 --depth 50
    """
    # Parse command-line arguments
    ap = argparse.ArgumentParser(
        description="Comprehensive local security audit for localhost applications",
        epilog="IMPORTANT: Intended for lawful local testing only. Keep findings confidential."
    )
    ap.add_argument("--target", "-t", default="http://localhost:8000",
                    help="Target localhost URL to scan")
    ap.add_argument("--root", "-r", default=".",
                    help="Repository root directory for static analysis")
    ap.add_argument("--out", "-o", default="audit_report.json",
                    help="Output JSON report filename")
    ap.add_argument("--enable-playwright", action="store_true",
                    help="Enable Playwright browser runtime checks")
    ap.add_argument("--enable-pcap", action="store_true",
                    help="Enable packet capture (requires admin/root)")
    ap.add_argument("--pcap-timeout", type=int, default=12,
                    help="Packet capture duration in seconds")
    ap.add_argument("--depth", type=int, default=300,
                    help="Maximum pages to crawl")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    target = args.target.rstrip("/")

    # Initialize report structure
    report = {
        "meta": {
            "root": root,
            "target": target,
            "time": time.asctime(),
            "playwright": args.enable_playwright,
            "pcap": args.enable_pcap
        },
        "findings": []
    }

    print("=" * 60)
    print("LOCAL SECURITY AUDIT TOOL")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Root:   {root}")
    print(f"Output: {args.out}")
    print("=" * 60)

    # PHASE 1: Static file analysis
    print("\n[PHASE 1/5] Static File Scan")
    print("-" * 60)
    static_findings = scan_files(root)
    print(f"✓ Found {len(static_findings)} potential secrets in files")
    report["findings"].extend(static_findings)

    # PHASE 2: Git history analysis
    print("\n[PHASE 2/5] Git History Scan")
    print("-" * 60)
    git_findings = scan_git_history(root)
    print(f"✓ Found {len(git_findings)} potential secrets in git history")
    report["findings"].extend(git_findings)

    # PHASE 3: HTTP crawler + JavaScript analysis
    print(f"\n[PHASE 3/5] Web Crawler ({target})")
    print("-" * 60)
    try:
        crawler = LocalCrawler(target, max_pages=args.depth)
        crawler.probe_common_paths()  # Check for exposed sensitive files
        crawler.crawl()  # Main crawl
        print(f"✓ Crawled {len(crawler.visited)} pages")
        print(f"✓ Found {len(crawler.findings)} potential issues")
        report["findings"].extend(crawler.findings)
    except Exception as e:
        print(f"✗ Crawler failed: {e}")
        report["crawler_error"] = str(e)

    # PHASE 4: Playwright runtime checks (optional)
    print("\n[PHASE 4/5] Browser Runtime Checks")
    print("-" * 60)
    if args.enable_playwright:
        pw = playwright_inspect(target)
        report["playwright"] = pw
        
        if isinstance(pw, dict) and "error" not in pw:
            print("✓ Playwright inspection complete")
            
            # Analyze browser storage for secrets
            storage_findings = 0
            
            for k, v in pw.get("localStorage", {}).items():
                sc, rs, ent = score_literal(str(v), k)
                if sc >= SCORE_THRESHOLD:
                    report["findings"].append({
                        "type": "playwright_localStorage",
                        "key": k,
                        "snippet": str(v)[:400],
                        "score": sc,
                        "reasons": rs
                    })
                    storage_findings += 1
            
            for k, v in pw.get("sessionStorage", {}).items():
                sc, rs, ent = score_literal(str(v), k)
                if sc >= SCORE_THRESHOLD:
                    report["findings"].append({
                        "type": "playwright_sessionStorage",
                        "key": k,
                        "snippet": str(v)[:400],
                        "score": sc,
                        "reasons": rs
                    })
                    storage_findings += 1
            
            for c in pw.get("cookies", []):
                val = c.get("value", "")
                sc, rs, ent = score_literal(val, c.get("name", ""))
                if sc >= SCORE_THRESHOLD:
                    report["findings"].append({
                        "type": "playwright_cookie",
                        "cookie": c,
                        "score": sc,
                        "reasons": rs
                    })
                    storage_findings += 1
            
            print(f"✓ Found {storage_findings} suspicious items in browser storage")
        else:
            print(f"✗ Playwright failed: {pw.get('error', 'unknown error')}")
    else:
        print("⊘ Playwright checks disabled (use --enable-playwright to enable)")

    # PHASE 5: Packet capture (optional)
    print("\n[PHASE 5/5] Network Packet Capture")
    print("-" * 60)
    if args.enable_pcap:
        pc = run_packet_capture(timeout=args.pcap_timeout)
        report["pcap"] = pc
        
        if "error" not in pc:
            print(f"✓ Captured {pc.get('captured', 0)} packets")
            
            # Analyze captured payloads for secrets
            pcap_findings = 0
            for entry in pcap_capture_results:
                payload = entry.get("payload", "")
                
                # Check against known patterns
                for name, pat in KNOWN_PATTERNS.items():
                    if pat.search(payload):
                        report["findings"].append({
                            "type": "pcap_pattern",
                            "pattern": name,
                            "payload_snippet": payload[:800]
                        })
                        pcap_findings += 1
                
                # Extract and score string literals from captured traffic
                for s, ctx in extract_string_literals(payload):
                    sc, rs, ent = score_literal(s, ctx)
                    if sc >= SCORE_THRESHOLD:
                        report["findings"].append({
                            "type": "pcap_literal",
                            "snippet": s[:400],
                            "score": sc,
                            "reasons": rs
                        })
                        pcap_findings += 1
            
            print(f"✓ Found {pcap_findings} suspicious patterns in network traffic")
        else:
            print(f"✗ Packet capture failed: {pc.get('message', 'unknown error')}")
    else:
        print("⊘ Packet capture disabled (use --enable-pcap to enable)")

    # PHASE 6: Deduplication
    print("\n[PROCESSING] Deduplicating findings...")
    uniq = []
    seen = set()
    for f in report["findings"]:
        # Create deduplication key from identifying fields
        key = json.dumps({
            k: v for k, v in f.items()
            if k in ("type", "file", "url", "pattern", "snippet", "key", "commit")
        }, sort_keys=True)
        
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    
    report["findings"] = uniq
    print(f"✓ Deduplicated {len(report['findings'])} unique findings")

    # PHASE 7: Generate summary statistics
    summary = defaultdict(int)
    for f in report["findings"]:
        summary[f.get("type", "unknown")] += 1
    report["summary"] = dict(summary)

    # PHASE 8: Write JSON report
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"✓ Report written to {args.out}")

    # PHASE 9: Print prioritized console summary
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    
    # High-confidence findings are those with high scores or known pattern matches
    high_conf = [
        f for f in report["findings"]
        if f.get("score", 0) >= 3 or
        f.get("type", "").startswith((
            "static_known", "js_literal", "header_pattern",
            "pcap_pattern", "git_match", "exposed_path"
        ))
    ]
    
    print(f"\nTotal Findings: {len(report['findings'])}")
    print(f"High Confidence: {len(high_conf)}")
    
    print("\nFindings by Category:")
    for t, c in sorted(report["summary"].items(), key=lambda x: -x[1]):
        print(f"  • {t:25s} {c:4d}")
    
    if high_conf:
        print(f"\nTop {min(20, len(high_conf))} High-Confidence Findings:")
        print("-" * 60)
        for i, h in enumerate(high_conf[:20], 1):
            location = h.get("file") or h.get("url") or h.get("commit", "")
            detail = h.get("pattern") or ", ".join(h.get("reasons", []))
            
            print(f"{i:2d}. [{h.get('type')}]")
            print(f"    Location: {location}")
            if detail:
                print(f"    Details:  {detail}")
            
            snippet = h.get("snippet", "")
            if snippet:
                preview = snippet[:70] + "..." if len(snippet) > 70 else snippet
                print(f"    Preview:  {preview}")
            print()
    
    print("=" * 60)
    print("⚠️  SECURITY RECOMMENDATIONS")
    print("=" * 60)
    print("1. Rotate/revoke any real credentials found immediately")
    print("2. Never commit secrets to version control")
    print("3. Use environment variables or secret management tools")
    print("4. Add .env files to .gitignore")
    print("5. Run this tool in CI/CD to catch secrets early")
    print("6. Consider using git-secrets or similar pre-commit hooks")
    print("=" * 60)


if __name__ == "__main__":
    main()
