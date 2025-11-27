"""
Main CLI entry point for cybersec-scanner.

Provides command-line interface with YAML configuration support
and individual scanner commands.
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional

from ..__version__ import __version__
from ..exceptions import CyberSecScannerError
from .config import load_config, create_default_config, validate_config

# Colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    # Fallback if colorama not available
    class Fore:
        RED = YELLOW = GREEN = CYAN = LIGHTBLACK_EX = WHITE = LIGHTRED_EX = LIGHTBLUE_EX = ""
    class Style:
        RESET_ALL = BRIGHT = ""


def print_ok(msg):
    """Print success message in green."""
    print(f"{Fore.GREEN}[OK] {msg}{Style.RESET_ALL}")


def print_error(msg):
    """Print error message in red."""
    print(f"{Fore.RED}[ERROR] {msg}{Style.RESET_ALL}", file=sys.stderr)


def print_warn(msg):
    """Print warning message in yellow."""
    print(f"{Fore.YELLOW}[WARN] {msg}{Style.RESET_ALL}")


def print_info(msg):
    """Print info message in cyan."""
    print(f"{Fore.CYAN}[INFO] {msg}{Style.RESET_ALL}")


def print_phase(phase_num, title):
    """Print phase header."""
    print(f"\n{Fore.GREEN}[PHASE {phase_num}] {title}{Style.RESET_ALL}")


def print_skip(msg):
    """Print skipped message in gray."""
    print(f"{Fore.LIGHTBLACK_EX}  [{msg}] Skipped{Style.RESET_ALL}")


def cmd_scan(args):
    """Execute full scan with all enabled scanners."""
    from .. import scan_all
    
    try:
        print_phase(1, "Initializing Security Scan")
        
        if args.config:
            print_info(f"Loading config from {args.config}")
            config = load_config(args.config)
            validate_config(config)
            results = scan_all(config_file=args.config)
        else:
            # Use command-line arguments
            config = {
                "enable_git": args.git,
                "enable_web": args.web,
                "enable_mitm": args.mitm,
                "enable_runtime": args.runtime,
                "root": args.root,
                "target": args.target,
                "max_commits": args.max_commits,
                "mitm_traffic": args.mitm_traffic,
            }
            
            # Show enabled scanners
            enabled = []
            if args.git: enabled.append("Git")
            if args.web: enabled.append("Web")
            if args.mitm: enabled.append("MITM")
            if args.runtime: enabled.append("Runtime")
            if enabled:
                print_info(f"Enabled scanners: {', '.join(enabled)}")
            else:
                print_warn("No scanners enabled. Use --git, --web, --mitm, or --runtime")
            
            print_phase(2, "Running Scanners")
            results = scan_all(**config)
        
        # Save results
        output_file = args.output or "audit_report.json"
        all_findings = []
        for scanner_type, findings in results.items():
            all_findings.extend(findings)
        
        report = {"findings": all_findings}
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        # Print summary by scanner type
        print_phase(3, "Scan Results")
        print(f"{Fore.GREEN}Total findings: {len(all_findings)}{Style.RESET_ALL}")
        for scanner_type, findings in results.items():
            if findings:
                print(f"  {Fore.YELLOW}• {scanner_type}: {len(findings)} findings{Style.RESET_ALL}")
            else:
                print(f"  {Fore.LIGHTBLACK_EX}• {scanner_type}: 0 findings{Style.RESET_ALL}")
        print_ok(f"Report saved to: {output_file}")
        
        # Build RAG if enabled
        if args.enable_rag or (args.config and config.get("rag", {}).get("enabled")):
            print_phase(4, "Building Knowledge Graph")
            from ..rag import KnowledgeGraph
            kg = KnowledgeGraph()
            kg.build_from_audit(Path(output_file))
            kg.save()
            print_ok("Knowledge graph built successfully")
        
        return 0
    except CyberSecScannerError as e:
        print_error(str(e))
        return 1


def cmd_scan_git(args):
    """Execute git-only scan."""
    from .. import scan_git
    
    try:
        findings = scan_git(args.root, max_commits=args.max_commits)
        
        output_file = args.output or "git_findings.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({"findings": findings}, f, indent=2)
        
        print_ok(f"Git scan complete. Found {len(findings)} findings.")
        print_ok(f"Report saved to: {output_file}")
        return 0
    except Exception as e:
        print_error(f"Git scan failed: {e}")
        return 1


def cmd_scan_web(args):
    """Execute web-only scan."""
    from .. import scan_web
    
    try:
        findings = scan_web(args.url, max_pages=args.max_pages)
        
        output_file = args.output or "web_findings.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({"findings": findings}, f, indent=2)
        
        print_ok(f"Web scan complete. Found {len(findings)} findings.")
        print_ok(f"Report saved to: {output_file}")
        return 0
    except Exception as e:
        print_error(f"Web scan failed: {e}")
        return 1


def cmd_scan_mitm(args):
    """Execute MITM traffic analysis."""
    from .. import scan_mitm
    
    try:
        findings = scan_mitm(args.traffic_file)
        
        output_file = args.output or "mitm_findings.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({"findings": findings}, f, indent=2)
        
        print_ok(f"MITM scan complete. Found {len(findings)} findings.")
        print_ok(f"Report saved to: {output_file}")
        return 0
    except Exception as e:
        print_error(f"MITM scan failed: {e}")
        return 1


def cmd_query(args):
    """Query findings using RAG system."""
    from ..rag import query_graph_and_llm, KnowledgeGraph, Retriever
    
    try:
        # Load or build graph
        graph_path = Path(args.graph or "rag/graph.gpickle")
        if not graph_path.exists():
            if not args.audit:
                print_error("No graph found. Provide --audit to build graph first.")
                return 1
            
            print_info(f"Building knowledge graph from {args.audit}...")
            kg = KnowledgeGraph()
            kg.build_from_audit(Path(args.audit))
            # Ensure directory exists
            graph_path.parent.mkdir(parents=True, exist_ok=True)
            saved_path = kg.save(graph_path)
            print_ok(f"Graph built successfully: {saved_path}")
        
        # Query
        print_info(f"Querying: {args.question}")
        print_info(f"Using model: {args.model}")
        response = query_graph_and_llm(
            args.question,
            graph_path=str(graph_path),
            model=args.model,
            k=args.top_k,
        )
        
        # Extract text from response (handle dict or string)
        if isinstance(response, dict):
            answer_text = response.get('text', response.get('raw', str(response)))
        else:
            answer_text = str(response)
        
        # Format and display answer
        separator = f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}"
        print(f"\n{separator}")
        print(f"{Fore.WHITE}{answer_text}{Style.RESET_ALL}")
        print(separator)
        
        # Save to file if --output specified
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"Query: {args.question}\n")
                f.write(f"Model: {args.model}\n")
                f.write(f"{'='*60}\n\n")
                f.write(answer_text)
                f.write(f"\n\n{'='*60}\n")
            print_ok(f"Response saved to: {output_path}")
        
        return 0
    except Exception as e:
        print_error(f"Query failed: {e}")
        return 1


def cmd_build_graph(args):
    """Build knowledge graph from audit report."""
    from ..rag import KnowledgeGraph
    
    try:
        audit_path = Path(args.audit)
        if not audit_path.exists():
            print_error(f"Audit report not found: {audit_path}")
            return 1
        
        print_info(f"Building knowledge graph from {audit_path}...")
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        
        output_path = Path(args.output) if args.output else Path("rag/graph.gpickle")
        kg.save(output_path)
        
        stats = kg.stats()
        print_ok("Knowledge graph built successfully")
        print(f"  {Fore.CYAN}Findings: {stats['findings']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}CWE nodes: {stats['cwes']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}OWASP nodes: {stats['owasps']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Saved to: {output_path}{Style.RESET_ALL}")
        return 0
    except Exception as e:
        print_error(f"Graph building failed: {e}")
        return 1


def cmd_init_config(args):
    """Create default configuration file."""
    output = args.output or "cybersec-config.yaml"
    try:
        create_default_config(output)
        print_ok(f"Created configuration file: {output}")
        print_info(f"Edit this file and use: cybersec-scanner scan --config {output}")
        return 0
    except Exception as e:
        print_error(f"Failed to create config: {e}")
        return 1


def cmd_version(args):
    """Show version information."""
    from ..__version__ import __title__, __description__
    print(f"{Fore.CYAN}{__title__}{Style.RESET_ALL} v{Fore.GREEN}{__version__}{Style.RESET_ALL}")
    print(__description__)
    return 0


def cmd_install_mitm_cert(args):
    """Install mitmproxy CA certificate to system trust store."""
    try:
        from ..scanners.install_mitm_cert import main as install_cert_main
        import sys
        # Temporarily replace sys.argv to pass args to install script
        old_argv = sys.argv
        sys.argv = ["install_mitm_cert"]
        if args.port:
            sys.argv.extend(["--port", str(args.port)])
        if args.no_download:
            sys.argv.append("--no-download")
        
        try:
            install_cert_main()
            return 0
        finally:
            sys.argv = old_argv
    except Exception as e:
        print(f"[ERROR] Certificate installation failed: {e}", file=sys.stderr)
        return 1


def cmd_start_proxy(args):
    """Start MITM proxy with automatic HTTP client patching."""
    try:
        print(f"Starting MITM proxy on port {args.port}...")
        from ..scanners.inject_mitm_proxy import inject_mitm_proxy_advanced
        import os
        
        os.environ["MITM_PROXY_PORT"] = str(args.port)
        
        # Clear traffic file if requested
        if args.traffic_file:
            from pathlib import Path
            traffic_path = Path(args.traffic_file)
            traffic_path.parent.mkdir(parents=True, exist_ok=True)
            traffic_path.write_text("")
            print(f"[OK] Traffic file cleared: {args.traffic_file}")
        
        inject_mitm_proxy_advanced()
        
        print(f"\n[OK] MITM Proxy is active on http://127.0.0.1:{args.port}")
        print(f"[OK] HTTP client libraries auto-patched (requests, httpx, urllib, aiohttp)")
        if args.traffic_file:
            print(f"[OK] Traffic logging to: {args.traffic_file}")
        print("\n[INFO] Run your application now. Press Ctrl+C to stop.")
        
        # Keep alive until user stops
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[OK] Proxy stopped by user")
            return 0
            
    except Exception as e:
        print(f"[ERROR] Proxy startup failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="cybersec-scanner",
        description="Comprehensive security scanner and vulnerability analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command (full scan with config)
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("--config", "-c", help="YAML configuration file")
    scan_parser.add_argument("--output", "-o", help="Output file for audit report")
    scan_parser.add_argument("--git", action="store_true", help="Enable git scanner")
    scan_parser.add_argument("--web", action="store_true", help="Enable web scanner")
    scan_parser.add_argument("--mitm", action="store_true", help="Enable MITM scanner")
    scan_parser.add_argument("--runtime", action="store_true", help="Enable runtime scanner")
    scan_parser.add_argument("--root", default=".", help="Root directory for git scan")
    scan_parser.add_argument("--target", help="Target URL for web scan")
    scan_parser.add_argument("--max-commits", type=int, default=50, help="Max git commits to scan")
    scan_parser.add_argument("--mitm-traffic", help="MITM traffic file path (default: temp dir auto-shared with backend)")
    scan_parser.add_argument("--enable-rag", action="store_true", help="Build knowledge graph after scan")
    scan_parser.set_defaults(func=cmd_scan)
    
    # Scan-git command (git only)
    git_parser = subparsers.add_parser("scan-git", help="Scan git repository only")
    git_parser.add_argument("root", nargs="?", default=".", help="Git repository path")
    git_parser.add_argument("--max-commits", type=int, default=50, help="Max commits to scan")
    git_parser.add_argument("--output", "-o", help="Output file")
    git_parser.set_defaults(func=cmd_scan_git)
    
    # Scan-web command (web only)
    web_parser = subparsers.add_parser("scan-web", help="Scan web application only")
    web_parser.add_argument("url", help="Target URL to scan")
    web_parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl")
    web_parser.add_argument("--output", "-o", help="Output file")
    web_parser.set_defaults(func=cmd_scan_web)
    
    # MITM scan command
    mitm_parser = subparsers.add_parser("scan-mitm", help="Scan MITM traffic logs")
    mitm_parser.add_argument("traffic_file", help="Path to mitm_traffic.ndjson file")
    mitm_parser.add_argument("--output", "-o", help="Output file")
    mitm_parser.set_defaults(func=cmd_scan_mitm)
    
    # Query command
    query_parser = subparsers.add_parser("query", help="Query findings using RAG")
    query_parser.add_argument("question", help="Question to ask")
    query_parser.add_argument("--audit", help="Audit report (if graph doesn't exist)")
    query_parser.add_argument("--graph", help="Knowledge graph file")
    query_parser.add_argument("--model", default="gemma3:1b", help="LLM model to use")
    query_parser.add_argument("--top-k", type=int, default=5, help="Number of findings to retrieve")
    query_parser.add_argument("--output", "-o", help="Save LLM response to file")
    query_parser.set_defaults(func=cmd_query)
    
    # Build-graph command
    graph_parser = subparsers.add_parser("build-graph", help="Build knowledge graph from audit report")
    graph_parser.add_argument("audit", help="Audit report JSON file")
    graph_parser.add_argument("--output", "-o", help="Output graph file")
    graph_parser.set_defaults(func=cmd_build_graph)
    
    # Init-config command
    config_parser = subparsers.add_parser("init-config", help="Create default configuration file")
    config_parser.add_argument("--output", "-o", help="Output config file path")
    config_parser.set_defaults(func=cmd_init_config)
    
    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=cmd_version)
    
    # MITM certificate installation command
    cert_parser = subparsers.add_parser("install-cert", help="Install mitmproxy CA certificate to system")
    cert_parser.add_argument("--port", type=int, default=8082, help="MITM proxy port (informational)")
    cert_parser.add_argument("--no-download", action="store_true", help="Skip HTTP download, use local cert only")
    cert_parser.set_defaults(func=cmd_install_mitm_cert)
    
    # MITM proxy start command
    proxy_parser = subparsers.add_parser("start-proxy", help="Start MITM proxy with auto-patching")
    proxy_parser.add_argument("--port", type=int, default=8082, help="Proxy listen port")
    proxy_parser.add_argument("--traffic-file", help="Traffic log file path (default: temp dir auto-shared)")
    proxy_parser.set_defaults(func=cmd_start_proxy)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
