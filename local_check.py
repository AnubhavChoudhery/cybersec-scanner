"""
Comprehensive local security audit tool.

Pattern-based secret detection across runtime and version control:
 - Git history analysis
 - HTTP crawling & JavaScript analysis
 - Optional browser runtime inspection (Playwright)
 - Optional network packet capture (Scapy)

USAGE:
  python local_check.py --target http://localhost:8000 --root . --out audit_report.json

  Optional flags:
    --enable-playwright    Enable browser runtime checks
    --enable-pcap         Enable packet capture (requires admin/root)
    --depth N             Maximum pages to crawl (default: 300)
    --max-commits N       Max commits per git search (default: 100)

Dependencies:
  Required: pip install requests
  Optional: pip install playwright scapy
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
from config import KNOWN_PATTERNS

# Import all scanners
from scanners import (
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
    ap.add_argument("--max-commits", type=int, default=100,
                    help="Maximum total commits to examine in git history (default: 100)")
    args = ap.parse_args()

    # Normalize root path: handle both Windows (C:\path) and Unix-style (/c/path) from Git Bash
    raw_root = args.root
    # If running in Git Bash on Windows, convert /c/Users/... to C:\Users\...
    if raw_root.startswith('/') and len(raw_root) > 2 and raw_root[2] == '/':
        # Looks like /c/path -> convert to C:\path
        drive_letter = raw_root[1].upper()
        raw_root = drive_letter + ':' + raw_root[2:].replace('/', '\\')
    
    root = os.path.abspath(raw_root)
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

    # PHASE 1: Git history analysis
    print("\n[PHASE 1/4] Git History Scan")
    print("-" * 60)
    git_findings = scan_git_history(root, max_commits=args.max_commits)
    print(f"[OK] Found {len(git_findings)} potential secrets in git history")
    report["findings"].extend(git_findings)

    # PHASE 2: HTTP crawler + JavaScript analysis
    print(f"\n[PHASE 2/4] Web Crawler ({target})")
    print("-" * 60)
    try:
        crawler = LocalCrawler(target, max_pages=args.depth)
        crawler.probe_common_paths()  # Check for exposed sensitive files
        crawler.crawl()  # Main crawl
        print(f"[OK] Crawled {len(crawler.visited)} pages")
        print(f"[OK] Found {len(crawler.findings)} potential issues")
        report["findings"].extend(crawler.findings)
    except Exception as e:
        print(f"[ERROR] Crawler failed: {e}")
        report["crawler_error"] = str(e)

    # PHASE 3: Playwright runtime checks (optional)
    print("\n[PHASE 3/4] Browser Runtime Checks")
    print("-" * 60)
    if args.enable_playwright:
        pw = playwright_inspect(target)
        report["playwright"] = pw
        
        if isinstance(pw, dict) and "error" not in pw:
            print("[OK] Playwright inspection complete")
            
            # Pattern match on browser storage
            storage_findings = 0
            
            for k, v in pw.get("localStorage", {}).items():
                val_str = str(v)
                for name, pat in KNOWN_PATTERNS.items():
                    try:
                        match = pat.search(val_str)
                        if match:
                            report["findings"].append({
                                "type": "playwright_localStorage",
                                "key": k,
                                "pattern": name,
                                "snippet": match.group(0)[:400]
                            })
                            storage_findings += 1
                    except Exception:
                        continue
            
            for k, v in pw.get("sessionStorage", {}).items():
                val_str = str(v)
                for name, pat in KNOWN_PATTERNS.items():
                    try:
                        match = pat.search(val_str)
                        if match:
                            report["findings"].append({
                                "type": "playwright_sessionStorage",
                                "key": k,
                                "pattern": name,
                                "snippet": match.group(0)[:400]
                            })
                            storage_findings += 1
                    except Exception:
                        continue
            
            for c in pw.get("cookies", []):
                val = c.get("value", "")
                for name, pat in KNOWN_PATTERNS.items():
                    try:
                        match = pat.search(val)
                        if match:
                            report["findings"].append({
                                "type": "playwright_cookie",
                                "cookie": c,
                                "pattern": name,
                                "snippet": match.group(0)[:400]
                            })
                            storage_findings += 1
                    except Exception:
                        continue
            
            print(f"[OK] Found {storage_findings} suspicious items in browser storage")
        else:
            print(f"[ERROR] Playwright failed: {pw.get('error', 'unknown error')}")
    else:
        print("[SKIP] Playwright checks disabled (use --enable-playwright to enable)")

    # PHASE 4: Packet capture (optional)
    print("\n[PHASE 4/4] Network Packet Capture")
    print("-" * 60)
    if args.enable_pcap:
        pc = run_packet_capture(timeout=args.pcap_timeout)
        report["pcap"] = pc
        
        if "error" not in pc:
            print(f"[OK] Captured {pc.get('captured', 0)} packets")
            
            # Pattern match on captured payloads
            pcap_findings = 0
            for entry in pcap_capture_results:
                payload = entry.get("payload", "")
                
                for name, pat in KNOWN_PATTERNS.items():
                    try:
                        match = pat.search(payload)
                        if match:
                            report["findings"].append({
                                "type": "pcap_pattern",
                                "pattern": name,
                                "snippet": match.group(0)[:400],
                                "payload_snippet": payload[:800]
                            })
                            pcap_findings += 1
                    except Exception:
                        continue
            
            print(f"[OK] Found {pcap_findings} suspicious patterns in network traffic")
        else:
            print(f"[ERROR] Packet capture failed: {pc.get('message', 'unknown error')}")
    else:
        print("[SKIP] Packet capture disabled (use --enable-pcap to enable)")

    # PHASE 5: Deduplication
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
    print(f"[OK] Deduplicated {len(report['findings'])} unique findings")

    # PHASE 6: Generate summary statistics
    summary = defaultdict(int)
    for f in report["findings"]:
        summary[f.get("type", "unknown")] += 1
    report["summary"] = dict(summary)

    # PHASE 7: Write JSON report
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[OK] Report written to {args.out}")

    # PHASE 8: Print prioritized console summary
    print("\n" + "=" * 60)
    print("AUDIT SUMMARY")
    print("=" * 60)
    
    # Pattern-based findings
    pattern_findings = [
        f for f in report["findings"]
        if f.get("pattern") or f.get("type", "").startswith((
            "js_pattern", "header_pattern", "response_pattern",
            "pcap_pattern", "git_pattern", "sourcemap_pattern",
            "exposed_path", "playwright_localStorage", 
            "playwright_sessionStorage", "playwright_cookie"
        ))
    ]
    
    print(f"\nTotal Findings: {len(report['findings'])}")
    print(f"Pattern Matches: {len(pattern_findings)}")
    
    print("\nFindings by Category:")
    for t, c in sorted(report["summary"].items(), key=lambda x: -x[1]):
        print(f"  • {t:25s} {c:4d}")
    
    if pattern_findings:
        print(f"\nTop {min(20, len(pattern_findings))} Pattern Matches:")
        print("-" * 60)
        for i, h in enumerate(pattern_findings[:20], 1):
            location = h.get("file") or h.get("url") or h.get("commit", "")
            pattern = h.get("pattern", "")
            
            print(f"{i:2d}. [{h.get('type')}]")
            print(f"    Location: {location}")
            if pattern:
                print(f"    Pattern:  {pattern}")
            
            snippet = h.get("snippet", "")
            if snippet:
                preview = snippet[:70] + "..." if len(snippet) > 70 else snippet
                print(f"    Match:    {preview}")
            print()
    
    print("=" * 60)
    print("[!] SECURITY RECOMMENDATIONS")
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
