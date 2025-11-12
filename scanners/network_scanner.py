#!/usr/bin/env python3
"""
Network scanner utilities used by local_check.py

- Proxy-aware HTTP client via get_proxied_session()
- ComprehensiveSecurityTester that uses the proxy session automatically
- Helper run_comprehensive_test() to drive active tests
- MITM proxy management for HTTPS traffic inspection

Intended for local development / audit flows.
"""

import os
import sys
import re
import time
import json
import subprocess
import tempfile
import socket
import shutil
import atexit
import signal
from datetime import datetime
from collections import defaultdict

# requests is required
try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install with: pip install requests")
    sys.exit(1)

# Colorama is optional
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init()
except Exception:
    class Fore:
        RED = ""
        LIGHTRED_EX = ""
        YELLOW = ""
        LIGHTBLUE_EX = ""
        LIGHTBLACK_EX = ""
        GREEN = ""
        CYAN = ""
        WHITE = ""
    class Style:
        RESET_ALL = ""

# Retry adapters for some resilience during tests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ------------------------------------------------------------------------------
# Pattern sources
# ------------------------------------------------------------------------------

# Main repo patterns (best-effort import; fallback to empty if missing)
try:
    from config import KNOWN_PATTERNS as PATTERN_CONFIG
except Exception:
    PATTERN_CONFIG = {}

# Network (wire-level) patterns used during content analysis
NETWORK_SECURITY_PATTERNS = {
    'password_plaintext': {
        'pattern': re.compile(r'(?i)"password"\s*:\s*"([^"]{1,})"|password=([^&\s]+)'),
        'severity': 'CRITICAL',
        'description': 'Password sent in plaintext'
    },
    'token_in_url': {
        'pattern': re.compile(r'[?&](token|access_token|auth_token|api_key)=([^&\s]+)'),
        'severity': 'HIGH',
        'description': 'Token/key in URL query parameter (should be in header)'
    },
    'bearer_token': {
        'pattern': re.compile(r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})'),
        'severity': 'INFO',
        'description': 'Bearer token (expected for auth)'
    },
    'basic_auth': {
        'pattern': re.compile(r'Basic\s+([a-zA-Z0-9+/=]{20,})'),
        'severity': 'MEDIUM',
        'description': 'Basic authentication detected'
    },
    'credit_card': {
        'pattern': re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        'severity': 'CRITICAL',
        'description': 'Possible credit card number'
    },
    'ssn': {
        'pattern': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'severity': 'CRITICAL',
        'description': 'Possible SSN'
    }
}

# ------------------------------------------------------------------------------
# Proxy-aware HTTP client
# ------------------------------------------------------------------------------

def get_proxied_session(proxy_port=None, verify_cert=True, timeout=10, use_env_proxy=False):
    """
    Return a requests.Session configured to use a mitm proxy if present.

    - If proxy_port is provided, uses http://127.0.0.1:<proxy_port> for both http/https
    - Else, if use_env_proxy=True and HTTP_PROXY/http_proxy present in env, uses that
    - verify_cert controls TLS verification (dev-mode often uses False)
    
    Note: By default, does NOT use environment proxy vars to avoid conflicts when
    MITM proxy is running but network tests shouldn't use it.
    """
    s = requests.Session()

    if proxy_port:
        proxy = f"http://127.0.0.1:{proxy_port}"
    elif use_env_proxy:
        proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    else:
        proxy = None

    if proxy:
        s.proxies.update({'http': proxy, 'https': proxy})

    s.verify = verify_cert

    # modest retry; do not mask real issues
    adapter = HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.1))
    s.mount('http://', adapter)
    s.mount('https://', adapter)

    # default per-request timeout convenience (not used by requests directly; we pass in test_endpoint)
    s.request_timeout = timeout
    return s

# ------------------------------------------------------------------------------
# MITM Proxy Management Functions
# ------------------------------------------------------------------------------

def _find_mitmdump_cmd():
    """Locate mitmdump in venv or PATH."""
    python_dir = os.path.dirname(os.path.realpath(sys.executable))
    candidates = [
        os.path.join(python_dir, 'mitmdump'),
        os.path.join(python_dir, 'mitmdump.exe'),
        'mitmdump'
    ]
    for c in candidates:
        if shutil.which(c):
            return c
    return None

def terminate_process(proc):
    """Safely terminate a process"""
    try:
        if proc and proc.poll() is None:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
    except Exception:
        pass

def run_mitm_proxy_background(port=8080, duration=None):
    """
    Start MITM proxy in background and return (process, results_file_path).
    The proxy will capture traffic to a results file.
    Call stop_mitm_proxy() or terminate the process when done.
    
    Returns: (process, results_file_path) or (None, error_dict) on failure
    """
    import signal
    
    # Check if mitmdump is available
    mitmdump_cmd = _find_mitmdump_cmd()
    if not mitmdump_cmd:
        return None, {
            "error": "mitmproxy-not-found",
            "message": "mitmdump not found. Install with: pip install mitmproxy"
        }
    
    # Create addon script
    addon_script = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
    addon_script_path = addon_script.name
    
    # Build patterns string (escape backslashes)
    patterns_str = "{\n"
    for name, config in NETWORK_SECURITY_PATTERNS.items():
        pattern_str = config['pattern'].pattern.replace('\\', '\\\\').replace("'", "\\'")
        patterns_str += f"    '{name}': {{\n"
        patterns_str += f"        'pattern': re.compile(r'''{pattern_str}'''),\n"
        patterns_str += f"        'severity': '{config['severity']}',\n"
        patterns_str += f"        'description': '{config['description']}'\n"
        patterns_str += f"    }},\n"
    patterns_str += "}"
    
    results_file = os.path.join(tempfile.gettempdir(), f'mitm_results_{port}.json')
    
    addon_code = f'''
import json
import re
from datetime import datetime
from mitmproxy import http

NETWORK_SECURITY_PATTERNS = {patterns_str}

findings = []
request_count = 0
response_count = 0
captured_traffic = []

class SecurityInspectorAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        global request_count, captured_traffic, findings
        request_count += 1
        req_data = {{
            'type': 'request',
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'timestamp': datetime.now().isoformat()
        }}
        if flow.request.content:
            try:
                req_data['body'] = flow.request.content.decode('utf-8', errors='ignore')[:10000]
            except:
                req_data['body'] = '<binary data>'
        captured_traffic.append(req_data)
        self._analyze(flow.request.pretty_url, 'URL', flow)
        for key, value in flow.request.headers.items():
            self._analyze(f"{{key}}: {{value}}", f'Request Header ({{key}})', flow)
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8', errors='ignore')
                self._analyze(content, 'Request Body', flow)
            except:
                pass
        print(f"[MITM] [→] {{flow.request.method}} {{flow.request.pretty_url[:80]}}")

    def response(self, flow: http.HTTPFlow) -> None:
        global response_count, captured_traffic, findings
        response_count += 1
        resp_data = {{
            'type': 'response',
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'timestamp': datetime.now().isoformat()
        }}
        if flow.response.content:
            try:
                resp_data['body'] = flow.response.content.decode('utf-8', errors='ignore')[:10000]
            except:
                resp_data['body'] = '<binary data>'
        captured_traffic.append(resp_data)
        for key, value in flow.response.headers.items():
            self._analyze(f"{{key}}: {{value}}", f'Response Header ({{key}})', flow)
        if flow.response.content:
            try:
                content = flow.response.content.decode('utf-8', errors='ignore')
                self._analyze(content, 'Response Body', flow)
            except:
                pass
        self._check_headers(flow)
        print(f"[MITM] [←] {{flow.response.status_code}} {{flow.request.pretty_url[:80]}}")

    def _analyze(self, content, context, flow):
        if not content: return
        for name, config in NETWORK_SECURITY_PATTERNS.items():
            try:
                matches = config['pattern'].findall(str(content))
                if matches:
                    finding = {{
                        'severity': config['severity'],
                        'category': name,
                        'description': config['description'],
                        'context': context,
                        'url': flow.request.pretty_url,
                        'timestamp': datetime.now().isoformat(),
                        'matches': len(matches)
                    }}
                    findings.append(finding)
                    print(f"[MITM] [!] {{config['severity']}} - {{name}} in {{context}}")
            except Exception:
                pass

    def _check_headers(self, flow):
        important = {{
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': '1; mode=block'
        }}
        for header in important:
            if header not in flow.response.headers:
                findings.append({{
                    'severity': 'LOW',
                    'category': 'missing_security_header',
                    'description': f'Missing security header: {{header}}',
                    'context': f'Response from {{flow.request.pretty_url}}',
                    'url': flow.request.pretty_url,
                    'timestamp': datetime.now().isoformat()
                }})

    def done(self):
        results = {{
            'requests': request_count,
            'responses': response_count,
            'findings': findings,
            'captured': len(captured_traffic),
            'traffic_sample': captured_traffic[:10],
            'severity_summary': {{}}
        }}
        for finding in findings:
            sev = finding['severity']
            results['severity_summary'][sev] = results['severity_summary'].get(sev, 0) + 1
        with open(r'{results_file.replace(chr(92), chr(92)*2)}', 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\\n[MITM] Proxy Stats: Requests={{request_count}}, Responses={{response_count}}, Findings={{len(findings)}}")

addons = [SecurityInspectorAddon()]
'''
    
    addon_script.write(addon_code)
    addon_script.close()
    
    # Clean old results file
    if os.path.exists(results_file):
        try:
            os.remove(results_file)
        except:
            pass
    
    # Start mitmdump
    cmd = [
        mitmdump_cmd,
        '-p', str(port),
        '-s', addon_script_path,
        '--set', 'stream_large_bodies=1',
        '--set', 'connection_strategy=lazy'
    ]
    
    try:
        print(f"{Fore.CYAN}[MITM] Starting proxy on port {port}...{Style.RESET_ALL}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=(os.setsid if hasattr(os, 'setsid') else None)
        )
        
        # Register cleanup
        atexit.register(lambda: terminate_process(process))
        
        # Wait for proxy to be ready
        time.sleep(3)
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            return None, {
                "error": "mitm-failed",
                "message": f"mitmproxy failed to start: {stdout}"
            }
        
        print(f"{Fore.GREEN}[MITM] ✓ Proxy running on port {port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[MITM] Capturing traffic... (results will be saved to {results_file}){Style.RESET_ALL}")
        
        # Return process and results file path
        return process, results_file
        
    except Exception as e:
        try:
            os.remove(addon_script_path)
        except:
            pass
        return None, {
            "error": "mitm-exception",
            "message": str(e)
        }

def stop_mitm_proxy(process, results_file, cleanup_addon=True):
    """
    Stop MITM proxy process and retrieve results.
    
    Returns: dict with findings or error dict
    """
    if not process:
        return {"error": "no-process", "message": "No MITM process to stop"}
    
    try:
        print(f"\n{Fore.CYAN}[MITM] Stopping proxy...{Style.RESET_ALL}")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except Exception as e:
        print(f"{Fore.YELLOW}[MITM] Warning during shutdown: {e}{Style.RESET_ALL}")
    
    # Give it a moment to write results
    time.sleep(1)
    
    # Read results
    if os.path.exists(results_file):
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            # Clean up results file
            try:
                os.remove(results_file)
            except:
                pass
            
            print(f"{Fore.GREEN}[MITM] ✓ Captured {results.get('requests', 0)} requests, {results.get('responses', 0)} responses{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[MITM] ✓ Found {results.get('total_findings', len(results.get('findings', [])))} security findings{Style.RESET_ALL}")
            
            return results
        except Exception as e:
            return {
                "error": "results-read-failed",
                "message": f"Failed to read results: {e}"
            }
    else:
        print(f"{Fore.YELLOW}[MITM] ⚠ No results file found (proxy may not have captured traffic){Style.RESET_ALL}")
        return {
            "requests": 0,
            "responses": 0,
            "findings": [],
            "captured": 0,
            "severity_summary": {},
            "warning": "No traffic captured"
        }

def print_mitm_instructions(port):
    """Print instructions for using MITM proxy with backend"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}MITM PROXY INSTRUCTIONS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}To capture your backend's HTTPS traffic:{Style.RESET_ALL}\n")
    print(f"{Fore.WHITE}In a separate terminal, set these environment variables BEFORE starting your backend:{Style.RESET_ALL}\n")
    
    # Bash/Linux/Mac
    print(f"{Fore.GREEN}  # For Bash/Linux/Mac:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export HTTP_PROXY=http://127.0.0.1:{port}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export HTTPS_PROXY=http://127.0.0.1:{port}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export NO_PROXY=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export REQUESTS_CA_BUNDLE=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export CURL_CA_BUNDLE=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}export SSL_CERT_FILE=''{Style.RESET_ALL}")
    
    # Windows CMD
    print(f"\n{Fore.GREEN}  # For Windows CMD:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set HTTP_PROXY=http://127.0.0.1:{port}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set HTTPS_PROXY=http://127.0.0.1:{port}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set NO_PROXY={Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set REQUESTS_CA_BUNDLE={Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set CURL_CA_BUNDLE={Style.RESET_ALL}")
    print(f"  {Fore.WHITE}set SSL_CERT_FILE={Style.RESET_ALL}")
    
    # Windows PowerShell
    print(f"\n{Fore.GREEN}  # For Windows PowerShell:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:HTTP_PROXY='http://127.0.0.1:{port}'{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:HTTPS_PROXY='http://127.0.0.1:{port}'{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:NO_PROXY=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:REQUESTS_CA_BUNDLE=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:CURL_CA_BUNDLE=''{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}$env:SSL_CERT_FILE=''{Style.RESET_ALL}")
    
    print(f"\n{Fore.WHITE}  Then start your backend:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}python your_backend.py{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTBLACK_EX}(or: node server.js, npm start, etc.){Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}These environment variables:{Style.RESET_ALL}")
    print(f"  • Route traffic through the MITM proxy")
    print(f"  • Disable SSL verification (dev/test only!)")
    print(f"  • Work with Python requests, urllib, Node.js, curl, etc.\n")
    
    print(f"{Fore.GREEN}Then interact with your app normally to generate traffic!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")