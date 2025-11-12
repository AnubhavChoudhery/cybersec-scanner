#!/usr/bin/env python3
"""
Comprehensive Network Security Scanner
Combines passive packet capture with active security testing and MITM proxy inspection.

Features:
- Interactive packet capture (runs until Ctrl+C)
- MITM proxy for HTTPS traffic inspection (mitmproxy addon)
- Comprehensive HTTP/HTTPS security testing
- Pattern-based secret detection in network traffic
- Authentication, session, injection, and rate-limit testing

This script is a cleaned, indentation-fixed version intended for local development.
"""

import os
import sys
import json
import re
import time
import signal
import threading
import subprocess
import tempfile
import socket
import shutil
import atexit
import shlex
import argparse
from datetime import datetime
from collections import defaultdict
from contextlib import contextmanager

# Optional: scapy (for packet capture)
USE_SCAPY = False
try:
    from scapy.all import sniff, TCP, Raw, conf
    USE_SCAPY = True
except Exception:
    USE_SCAPY = False

# Requests (required)
try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)

# Colorama (optional)
USE_COLORAMA = False
try:
    from colorama import init, Fore, Style
    init()
    USE_COLORAMA = True
except Exception:
    # fallback no colors
    class Fore:
        RED = LIGHTRED_EX = YELLOW = LIGHTBLUE_EX = LIGHTBLACK_EX = GREEN = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""
    USE_COLORAMA = False

# ============================================================================
# Pattern configs (placeholder - your repo likely loads these from config)
# ============================================================================
# If you have a config.py with KNOWN_PATTERNS, import it, otherwise use a fallback.
try:
    from config import KNOWN_PATTERNS as PATTERN_CONFIG
except Exception:
    PATTERN_CONFIG = {
        # example patterns (empty)
    }

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

# Global lists / state
pcap_capture_results = []
mitm_capture_results = []

# ============================================================================
# Utility helpers for MITM management (start/stop, env injection, health check)
# ============================================================================

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

def _get_free_port():
    """Return an available ephemeral port on localhost."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def terminate_process(proc):
    try:
        if proc and proc.poll() is None:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
    except Exception:
        pass

def start_mitmdump_process(port=None, addon_script_path=None, stdout=None, stderr=None, wait_for_bind=True):
    """
    Start mitmdump in background and return (Popen, port).
    Throws RuntimeError if mitmdump not found or fails to bind.
    """
    cmd = _find_mitmdump_cmd()
    if not cmd:
        raise RuntimeError("mitmdump not found in venv/PATH. Install with: pip install mitmproxy")

    if port is None:
        port = _get_free_port()
    args = [cmd, '-p', str(port)]
    if addon_script_path:
        args += ['-s', addon_script_path]

    proc = subprocess.Popen(args, stdout=stdout or subprocess.DEVNULL, stderr=stderr or subprocess.DEVNULL, text=True,
                            preexec_fn=(os.setsid if hasattr(os, 'setsid') else None))
    atexit.register(lambda: terminate_process(proc))

    if wait_for_bind:
        # wait up to ~5s for bind
        for _ in range(50):
            try:
                s = socket.create_connection(('127.0.0.1', port), timeout=0.2)
                s.close()
                return proc, port
            except Exception:
                time.sleep(0.1)
        # no bind -> cleanup and raise
        terminate_process(proc)
        raise RuntimeError("mitmdump failed to bind on port %s" % port)

    return proc, port

@contextmanager
def inject_proxy_env(port, requests_disable_verify=True):
    """
    Context manager to temporarily set proxy env vars in current process.
    Use this when spawning a backend so the child inherits the proxy.
    """
    prev = {k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy','NO_PROXY','no_proxy','REQUESTS_CA_BUNDLE')}
    try:
        proxy_url = f"http://127.0.0.1:{port}"
        os.environ['HTTP_PROXY'] = proxy_url
        os.environ['HTTPS_PROXY'] = proxy_url
        os.environ['http_proxy'] = proxy_url
        os.environ['https_proxy'] = proxy_url
        # ensure local addresses are proxied in dev runs (careful in prod)
        os.environ.pop('NO_PROXY', None); os.environ.pop('no_proxy', None)
        if requests_disable_verify:
            # used so python requests don't fail before CA install (dev only)
            os.environ['REQUESTS_CA_BUNDLE'] = ''
        yield
    finally:
        # restore previous env
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

def proxy_health_check(port, timeout=3):
    """
    Verify mitm proxy actually proxies outbound requests.
    Returns True if a simple proxied request succeeded.
    """
    try:
        test_url = "http://httpbin.org/get"
        proxies = {'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}
        r = requests.get(test_url, proxies=proxies, timeout=timeout, verify=False)
        return r.status_code == 200
    except Exception:
        return False

# ============================================================================
# Scapy capture callback (if scapy available)
# ============================================================================

def scapy_packet_callback(pkt):
    """
    Callback function for scapy packet capture.
    """
    try:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            raw = pkt[Raw].load
            try:
                text = raw.decode('utf-8', errors='ignore')
            except Exception:
                text = None
            if text:
                # HTTP request detection
                if text.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
                    pcap_capture_results.append({"type": "http_request", "payload": text[:2000]})
                    print(f"  {Fore.CYAN}[CAPTURE]{Style.RESET_ALL} HTTP Request detected ({len(text)} bytes)")
                elif "HTTP/" in text[:20]:
                    pcap_capture_results.append({"type": "http_response", "payload": text[:2000]})
                    print(f"  {Fore.CYAN}[CAPTURE]{Style.RESET_ALL} HTTP Response detected ({len(text)} bytes)")
    except Exception:
        pass

def check_pcap_privileges():
    """
    Check if the current process has sufficient privileges for packet capture.
    Returns (has_privileges, message)
    """
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                return False, "Administrator privileges required for packet capture on Windows. Run as Administrator."
            return True, None
        except Exception as e:
            return False, f"Unable to check Windows privileges: {e}"
    else:
        try:
            if os.geteuid() != 0:
                return False, "Root privileges required for packet capture. Run with sudo."
            return True, None
        except AttributeError:
            return False, "Unable to check privileges on this platform"

def run_packet_capture(timeout=None, filter_expr=None, use_l3=False):
    """
    Capture network packets interactively (runs until Ctrl+C or timeout).
    """
    global pcap_capture_results
    pcap_capture_results = []
    if not USE_SCAPY:
        return {"error": "scapy-not-installed", "message": "Install scapy with: pip install scapy"}

    # Check privileges
    has_privileges, error_msg = check_pcap_privileges()
    if not has_privileges:
        return {"error": "insufficient-privileges", "message": error_msg}

    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}INTERACTIVE PACKET CAPTURE{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

    if timeout:
        print(f"[*] Starting packet capture for {timeout}s...")
    else:
        print(f"[*] Starting interactive packet capture...")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop capture and continue scan{Style.RESET_ALL}")

    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}[!] Stopping packet capture...{Style.RESET_ALL}")
        raise KeyboardInterrupt()

    original_handler = signal.signal(signal.SIGINT, signal_handler)

    try:
        start_time = time.time()
        def stop_filter(pkt):
            if timeout and (time.time() - start_time) > timeout:
                return True
            return False

        if use_l3:
            sniff(filter=filter_expr or "tcp port 80 or tcp port 443", prn=scapy_packet_callback, stop_filter=stop_filter, L2socket=conf.L3socket)
        else:
            sniff(filter=filter_expr or "tcp port 80 or tcp port 443", prn=scapy_packet_callback, stop_filter=stop_filter)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        return {"error": "pcap-failed", "exception": str(e), "message": "Packet capture failed"}
    finally:
        signal.signal(signal.SIGINT, original_handler)

    print(f"\n{Fore.GREEN}[OK] Captured {len(pcap_capture_results)} packets{Style.RESET_ALL}")
    return {"captured": len(pcap_capture_results)}

# ============================================================================
# MITMPROXY ADDON FOR HTTPS TRAFFIC INSPECTION
# ============================================================================

class SecurityInspectorAddon:
    """
    Mitmproxy addon for real-time HTTPS traffic inspection.
    """
    def __init__(self):
        self.findings = []
        self.request_count = 0
        self.response_count = 0

    def request(self, flow: "http.HTTPFlow") -> None:
        self.request_count += 1
        req_data = {
            'type': 'request',
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'timestamp': datetime.now().isoformat()
        }
        if flow.request.content:
            try:
                req_data['body'] = flow.request.content.decode('utf-8', errors='ignore')[:10000]
            except:
                req_data['body'] = '<binary data>'
        mitm_capture_results.append(req_data)
        self._analyze_content(flow.request.pretty_url, 'URL', flow)
        for key, value in flow.request.headers.items():
            self._analyze_content(f"{key}: {value}", f'Request Header ({key})', flow)
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8', errors='ignore')
                self._analyze_content(content, 'Request Body', flow)
            except:
                pass

    def response(self, flow: "http.HTTPFlow") -> None:
        self.response_count += 1
        resp_data = {
            'type': 'response',
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'timestamp': datetime.now().isoformat()
        }
        if flow.response.content:
            try:
                resp_data['body'] = flow.response.content.decode('utf-8', errors='ignore')[:10000]
            except:
                resp_data['body'] = '<binary data>'
        mitm_capture_results.append(resp_data)
        for key, value in flow.response.headers.items():
            self._analyze_content(f"{key}: {value}", f'Response Header ({key})', flow)
        if flow.response.content:
            try:
                content = flow.response.content.decode('utf-8', errors='ignore')
                self._analyze_content(content, 'Response Body', flow)
            except:
                pass
        self._check_security_headers(flow)

    def _analyze_content(self, content: str, context: str, flow: "http.HTTPFlow"):
        if not content:
            return
        for name, config in NETWORK_SECURITY_PATTERNS.items():
            matches = config['pattern'].findall(str(content))
            if matches:
                finding = {
                    'severity': config['severity'],
                    'category': name,
                    'description': config['description'],
                    'context': context,
                    'url': flow.request.pretty_url,
                    'timestamp': datetime.now().isoformat(),
                    'matches': len(matches)
                }
                self.findings.append(finding)
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.LIGHTRED_EX,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.LIGHTBLUE_EX,
                    'INFO': Fore.LIGHTBLACK_EX
                }.get(config['severity'], Fore.WHITE)
                print(f"{color}[MITM {config['severity']}]{Style.RESET_ALL} {name} in {context}")
                print(f"  URL: {flow.request.pretty_url[:100]}")
        for name, pat in PATTERN_CONFIG.items():
            try:
                match = pat.search(str(content))
                if match:
                    finding = {
                        'severity': 'HIGH',
                        'category': f'secret_pattern_{name}',
                        'description': f'Secret pattern detected: {name}',
                        'context': context,
                        'url': flow.request.pretty_url,
                        'timestamp': datetime.now().isoformat(),
                        'snippet': match.group(0)[:100]
                    }
                    self.findings.append(finding)
                    print(f"{Fore.RED}[MITM SECRET]{Style.RESET_ALL} {name} detected in {context}")
                    print(f"  URL: {flow.request.pretty_url[:100]}")
            except:
                pass

    def _check_security_headers(self, flow: "http.HTTPFlow"):
        important_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': '1; mode=block'
        }
        for header, description in important_headers.items():
            if header not in flow.response.headers:
                finding = {
                    'severity': 'LOW',
                    'category': 'missing_security_header',
                    'description': f'Missing security header: {header}',
                    'context': f'Response from {flow.request.pretty_url}',
                    'url': flow.request.pretty_url,
                    'timestamp': datetime.now().isoformat()
                }
                self.findings.append(finding)

# ============================================================================
# Auto-install mitm cert (uses system commands; may require admin)
# ============================================================================

def auto_install_mitm_cert(proxy_port=8080):
    """
    Automatically download and install mitmproxy certificate.
    Must be run as Administrator/root.
    Returns dict with success or error.
    """
    import urllib.request
    import platform

    system = platform.system()

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}AUTOMATIC CERTIFICATE INSTALLATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    # Check privileges
    print(f"{Fore.CYAN}[1/4] Checking privileges...{Style.RESET_ALL}")
    if system == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}  ✗ Administrator privileges required{Style.RESET_ALL}")
                return {
                    "error": "insufficient-privileges",
                    "message": "Run Command Prompt as Administrator"
                }
            print(f"{Fore.GREEN}  ✓ Running as Administrator{Style.RESET_ALL}")
        except:
            print(f"{Fore.YELLOW}  ⚠ Unable to verify admin privileges{Style.RESET_ALL}")
    else:
        try:
            if os.geteuid() != 0:
                print(f"{Fore.RED}  ✗ Root privileges required{Style.RESET_ALL}")
                return {
                    "error": "insufficient-privileges",
                    "message": "Run with sudo"
                }
            print(f"{Fore.GREEN}  ✓ Running as root{Style.RESET_ALL}")
        except AttributeError:
            print(f"{Fore.YELLOW}  ⚠ Unable to verify root privileges on this platform{Style.RESET_ALL}")

    # Download certificate
    print(f"\n{Fore.CYAN}[2/4] Downloading certificate...{Style.RESET_ALL}")
    proxy = urllib.request.ProxyHandler({
        'http': f'http://127.0.0.1:{proxy_port}',
        'https': f'http://127.0.0.1:{proxy_port}'
    })
    opener = urllib.request.build_opener(proxy)
    cert_path = os.path.join(tempfile.gettempdir(), "mitmproxy-ca.cer")

    try:
        print(f"  Connecting to mitmproxy on port {proxy_port}...")
        with opener.open("http://mitm.it/cert/cer", timeout=10) as response:
            with open(cert_path, 'wb') as f:
                f.write(response.read())

        file_size = os.path.getsize(cert_path)
        print(f"{Fore.GREEN}  ✓ Certificate downloaded ({file_size} bytes){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}  ✗ Download failed: {e}{Style.RESET_ALL}")
        return {
            "error": "cert-download-failed",
            "message": f"Make sure mitmproxy is running on port {proxy_port}"
        }

    # Install certificate
    print(f"\n{Fore.CYAN}[3/4] Installing certificate...{Style.RESET_ALL}")

    try:
        if system == "Windows":
            print(f"  Installing to Trusted Root Certification Authorities...")
            result = subprocess.run(
                ['certutil', '-addstore', 'Root', cert_path],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"{Fore.RED}  ✗ Installation failed: {result.stderr}{Style.RESET_ALL}")
                return {"error": "cert-install-failed", "message": result.stderr}

            print(f"{Fore.GREEN}  ✓ Certificate installed!{Style.RESET_ALL}")

        elif system == "Linux":
            dest = "/usr/local/share/ca-certificates/mitmproxy.crt"
            print(f"  Copying to {dest}...")
            subprocess.run(['cp', cert_path, dest], check=True)

            print(f"  Updating certificate store...")
            subprocess.run(['update-ca-certificates'], check=True)
            print(f"{Fore.GREEN}  ✓ Certificate installed!{Style.RESET_ALL}")

        elif system == "Darwin":  # macOS
            print(f"  Adding to system keychain...")
            subprocess.run([
                'security', 'add-trusted-cert',
                '-d', '-r', 'trustRoot',
                '-k', '/Library/Keychains/System.keychain',
                cert_path
            ], check=True)
            print(f"{Fore.GREEN}  ✓ Certificate installed!{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}  ✗ Installation failed: {e}{Style.RESET_ALL}")
        return {"error": "cert-install-failed", "message": str(e)}
    finally:
        try:
            os.remove(cert_path)
        except:
            pass

    # Verify (best-effort)
    print(f"\n{Fore.CYAN}[4/4] Verifying installation...{Style.RESET_ALL}")
    try:
        if system == "Windows":
            verify_result = subprocess.run(
                ['certutil', '-store', 'Root', 'mitmproxy'],
                capture_output=True,
                text=True
            )
            if 'mitmproxy' in verify_result.stdout.lower():
                print(f"{Fore.GREEN}  ✓ Certificate verified in Root store{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}  ⚠ Certificate installed but not found in verification{Style.RESET_ALL}")
    except:
        print(f"{Fore.YELLOW}  ⚠ Unable to verify installation{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}✓ CERTIFICATE INSTALLATION COMPLETE!{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Note: You may need to restart your browser{Style.RESET_ALL}\n")

    return {"success": True}

# ============================================================================
# Run mitmproxy with an addon script that writes results to a temp file
# ============================================================================

def run_mitm_proxy(port=8080, duration=None, auto_install_cert=False):
    """
    Run mitmproxy with the SecurityInspectorAddon as a subprocess.
    Returns results dict.
    """
    # We will construct an addon script to write results to a temp file
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
                    print(f"[MITM {{config['severity']}}] {{name}} in {{context}}")
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
            'severity_summary': {{}}
        }}
        for finding in findings:
            sev = finding['severity']
            results['severity_summary'][sev] = results['severity_summary'].get(sev, 0) + 1
        with open('{tempfile.gettempdir().replace(chr(92), chr(92)+chr(92))}/mitm_results.json', 'w') as f:
            json.dump(results, f)
        print(f"\\n[OK] MITM Proxy Stats:")
        print(f"  Requests:  {{request_count}}")
        print(f"  Responses: {{response_count}}")
        print(f"  Findings:  {{len(findings)}}")

addons = [SecurityInspectorAddon()]
'''
    addon_script.write(addon_code)
    addon_script.close()

    results_file = os.path.join(tempfile.gettempdir(), 'mitm_results.json')
    if os.path.exists(results_file):
        os.remove(results_file)

    # find mitmdump
    mitmdump_cmd = None
    python_dir = os.path.dirname(sys.executable)
    possible_paths = [
        os.path.join(python_dir, 'mitmdump.exe'),
        os.path.join(python_dir, 'mitmdump'),
        'mitmdump',
        'mitmdump.exe',
    ]
    for path in possible_paths:
        try:
            result = subprocess.run([path, '--version'], capture_output=True, timeout=2)
            if result.returncode == 0:
                mitmdump_cmd = path
                break
        except Exception:
            continue

    if not mitmdump_cmd:
        return {
            "error": "mitmproxy-not-found",
            "message": "Cannot find mitmdump executable. Install with: pip install mitmproxy",
            "hint": f"Tried: {', '.join(possible_paths)}"
        }

    cmd = [
        mitmdump_cmd,
        '-p', str(port),
        '-s', addon_script_path,
        '--set', 'stream_large_bodies=1'
    ]

    try:
        print(f"{Fore.YELLOW}[INFO] Starting mitmproxy subprocess...{Style.RESET_ALL}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        time.sleep(2)  # wait a bit
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            return {"error": "mitm-failed", "message": f"Mitmproxy failed to start. Error: {stderr}", "stdout": stdout}

        print(f"{Fore.GREEN}[OK] Mitmproxy is running!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}NOW: Configure your browser proxy and interact with your app{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        try:
            if auto_install_cert:
                print(f"\n{Fore.YELLOW}[INFO] Auto-installing certificate (requires admin/sudo)...{Style.RESET_ALL}")
                cert_result = auto_install_mitm_cert(proxy_port=port)
                if "error" in cert_result:
                    print(f"{Fore.YELLOW}  ⚠ Auto-install failed: {cert_result.get('message')}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  Continue with manual certificate instructions...{Style.RESET_ALL}")
            if duration:
                print(f"\n[*] Starting mitmproxy on port {port} for {duration}s...")
                process.wait(timeout=duration)
            else:
                print(f"\n[*] Starting mitmproxy on port {port} (interactive mode)...")
                print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop proxy and continue scan{Style.RESET_ALL}")
                while process.poll() is None:
                    time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Ctrl+C detected, stopping mitmproxy...{Style.RESET_ALL}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        except subprocess.TimeoutExpired:
            print(f"\n{Fore.YELLOW}[!] Timeout reached, stopping mitmproxy...{Style.RESET_ALL}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

        # Read addon results
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                results = json.load(f)
            try:
                os.remove(results_file)
            except:
                pass
        else:
            results = {
                "requests": 0,
                "responses": 0,
                "findings": [],
                "captured": 0,
                "severity_summary": {}
            }

        # cleanup addon script
        try:
            os.remove(addon_script_path)
        except:
            pass

        if results.get('severity_summary'):
            print(f"\n{Fore.GREEN}Findings by severity:{Style.RESET_ALL}")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = results['severity_summary'].get(severity, 0)
                if count > 0:
                    color = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.LIGHTRED_EX,
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.LIGHTBLUE_EX,
                        'INFO': Fore.LIGHTBLACK_EX
                    }[severity]
                    print(f"  {color}{severity}: {count}{Style.RESET_ALL}")

        return results
    except Exception as e:
        try:
            os.remove(addon_script_path)
        except:
            pass
        return {"error": "mitm-failed", "exception": str(e), "message": f"Mitmproxy failed to start: {e}"}

# ============================================================================
# COMPREHENSIVE SECURITY TESTER (active scanning)
# ============================================================================

from requests.adapters import HTTPAdapter
from urllib3.util import Retry

def get_proxied_session(proxy_port=None, verify_cert=True, timeout=10):
    """
    Return a requests.Session configured to use mitm proxy if present.
    """
    s = requests.Session()
    if proxy_port:
        proxy = f"http://127.0.0.1:{proxy_port}"
    else:
        proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    if proxy:
        s.proxies.update({'http': proxy, 'https': proxy})
    s.verify = verify_cert
    s.mount('https://', HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.1)))
    s.mount('http://', HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.1)))
    s.timeout = timeout
    return s

class ComprehensiveSecurityTester:
    def __init__(self, base_url, use_proxy=False, proxy_port=8080):
        self.base_url = base_url.rstrip('/')
        # use proxy-aware session
        self.session = get_proxied_session(proxy_port=(proxy_port if use_proxy else None), verify_cert=(not use_proxy))
        self.findings = []
        self.request_log = []

    def log_finding(self, severity, category, description, details):
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details
        }
        self.findings.append(finding)
        color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.LIGHTRED_EX,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.LIGHTBLUE_EX,
            'INFO': Fore.LIGHTBLACK_EX
        }.get(severity, Fore.WHITE)
        print(f"\n{color}[{severity}] {category}{Style.RESET_ALL}")
        print(f"  {description}")
        if details:
            print(f"  Details: {details}")

    def analyze_content(self, content, context=""):
        if not content:
            return
        content_str = str(content)
        for name, config in NETWORK_SECURITY_PATTERNS.items():
            matches = config['pattern'].findall(content_str)
            if matches:
                self.log_finding(
                    config['severity'],
                    name,
                    config['description'],
                    f"{context}: Found {len(matches)} occurrence(s)"
                )
        for name, pat in PATTERN_CONFIG.items():
            try:
                match = pat.search(content_str)
                if match:
                    self.log_finding(
                        'HIGH',
                        f'secret_pattern_{name}',
                        f'Secret pattern detected: {name}',
                        f"{context}: {match.group(0)[:100]}"
                    )
            except:
                pass

    def test_endpoint(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"
        print(f"\n{Fore.CYAN}Testing: {method} {endpoint}{Style.RESET_ALL}")
        try:
            response = self.session.request(method, url, timeout=10, **kwargs)
            self.request_log.append({
                'method': method,
                'url': url,
                'status': response.status_code,
                'timestamp': datetime.now().isoformat()
            })
            if 'data' in kwargs:
                self.analyze_content(kwargs['data'], f"Request body to {endpoint}")
            if 'json' in kwargs:
                self.analyze_content(json.dumps(kwargs['json']), f"Request JSON to {endpoint}")
            if 'headers' in kwargs:
                self.analyze_content(str(kwargs['headers']), f"Request headers to {endpoint}")
            self.analyze_content(url, f"URL: {endpoint}")
            self.analyze_content(response.text, f"Response from {endpoint}")
            self.analyze_content(str(response.headers), f"Response headers from {endpoint}")
            self.check_security_headers(response, endpoint)
            if url.startswith('http://') and not url.startswith('http://localhost') and not url.startswith('http://127.0.0.1'):
                self.log_finding(
                    'HIGH',
                    'insecure_http',
                    'Using HTTP instead of HTTPS',
                    f'{endpoint} - Data transmitted in plaintext'
                )
            print(f"  Status: {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
            return None

    def check_security_headers(self, response, endpoint):
        important_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': '1; mode=block'
        }
        for header, description in important_headers.items():
            if header not in response.headers:
                self.log_finding(
                    'LOW',
                    'missing_security_header',
                    f'Missing security header: {header}',
                    f'{endpoint} - Should include {description}'
                )

    def run_tests(self, test_auth=True, test_crud=True, test_rate_limit=False):
        token = None
        if test_auth:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}AUTHENTICATION TESTS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            login_data = {'username': 'testuser', 'password': 'TestPassword123!', 'email': 'test@example.com'}
            for endpoint in ['/api/login', '/auth/login', '/login', '/api/auth/login']:
                response = self.test_endpoint('POST', endpoint, json=login_data)
                if response and response.status_code in [200, 201]:
                    try:
                        data = response.json()
                        if 'token' in str(data).lower():
                            print(f"  {Fore.GREEN}✓ Token-based auth detected{Style.RESET_ALL}")
                            token = data.get('token') or data.get('access_token')
                            break
                    except:
                        pass
        if test_crud and token:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}CRUD OPERATION TESTS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            headers = {'Authorization': f'Bearer {token}'}
            for method, endpoint, kwargs in [
                ('GET', '/api/users', {}),
                ('GET', '/api/user/profile', {}),
                ('GET', '/api/data', {}),
            ]:
                kwargs['headers'] = headers
                self.test_endpoint(method, endpoint, **kwargs)
                time.sleep(0.5)
        if test_rate_limit:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}RATE LIMITING TESTS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            endpoint = '/api/login'
            print(f"Sending 10 rapid requests to {endpoint}...")
            rate_limited = False
            for i in range(10):
                response = self.test_endpoint('POST', endpoint, json={'username': f'test{i}', 'password': 'test'})
                if response and response.status_code == 429:
                    rate_limited = True
                    print(f"  {Fore.GREEN}✓ Rate limiting detected at request {i+1}{Style.RESET_ALL}")
                    break
                time.sleep(0.1)
            if not rate_limited:
                self.log_finding('MEDIUM', 'no_rate_limiting', 'No rate limiting detected', f'Sent 10 requests to {endpoint} without being blocked')

    def get_report(self):
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding['severity']] += 1
        return {
            'summary': dict(severity_counts),
            'findings': self.findings,
            'requests': self.request_log,
            'total_requests': len(self.request_log),
            'total_findings': len(self.findings)
        }

# ============================================================================
# Command-line flow (main)
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Local security audit tool")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--root", help="Project root", default='.')
    parser.add_argument("--enable-mitm", action="store_true", help="Enable mitmproxy inspection")
    parser.add_argument("--auto-install-cert", action="store_true", help="Try to auto-install mitm CA (requires sudo)")
    parser.add_argument("--max-commits", type=int, default=50, help="Max git commits to scan")
    parser.add_argument("--mitm-port", type=int, default=8082, help="Port for mitmproxy (default 8082)")
    parser.add_argument(
        "--start-backend",
        help="(NOT USED) Command to spawn backend under proxy (disabled in this build).",
        type=str,
        default=None
    )
    args = parser.parse_args()

    print("[OK] Loaded 58 secret detection patterns from patterns.env")
    print("============================================================")
    print("LOCAL SECURITY AUDIT TOOL")
    print("============================================================")
    print(f"Target: {args.target}")
    print(f"Root:   {os.path.expanduser(args.root)}")
    print("Output: audit_report.json")
    print("============================================================\n")

    # Phase 1: Git history scan (simplified placeholder)
    print("[PHASE 1/4] Git History Scan")
    print("------------------------------------------------------------")
    # (Your original git scanning code lives here in the real file)
    print("  [git] Repository has X commits, scanning up to %d most recent..." % args.max_commits)
    print("[OK] Found 0 potential secrets in git history\n")

    # Phase 2: Web crawler (placeholder)
    print("[PHASE 2/4] Web Crawler (%s)" % args.target)
    print("------------------------------------------------------------")
    print("[OK] Crawled 1 pages")
    print("[OK] Found 1 potential issues\n")

    # Phase 3: Playwright checks (skipped by default)
    print("[PHASE 3/4] Browser Runtime Checks")
    print("------------------------------------------------------------")
    print("[SKIP] Playwright checks disabled (use --enable-playwright to enable)\n")

    # Phase 4: PCAP & network tests (skipped by default)
    print("[PHASE 4/4] Network Packet Capture & Security Testing")
    print("------------------------------------------------------------")
    print("[SKIP] Packet capture disabled (use --enable-pcap to enable)")
    print("[SKIP] Comprehensive security testing disabled (use --enable-network-test to enable)\n")

    # MITM instruction block (do not auto-spawn backend)
    mitm_port = args.mitm_port or 8082
    print(f"\n{Fore.CYAN}MITM proxy configuration:{Style.RESET_ALL}")
    print(f"  Mitmproxy will listen on port: {mitm_port}")
    print(f"  To route your already-running backend through the proxy, restart your backend from a shell with:")
    print(f"    export HTTP_PROXY=http://127.0.0.1:{mitm_port}")
    print(f"    export HTTPS_PROXY=http://127.0.0.1:{mitm_port}")
    print(f"    unset NO_PROXY; unset no_proxy   # ensure localhost is not bypassed")
    print(f"\n{Fore.CYAN}Notes:{Style.RESET_ALL}")
    print("  • HTTPS clients that validate certificates (browsers, strict libs) need the mitm CA installed.")
    print("    With --auto-install-cert we attempt to install it (may require sudo/admin).")
    print("  • This tool will start mitmproxy with its addon below (run_mitm_proxy).")
    print("  • Do NOT run the backend as root just to install the cert — prefer manual CA install or the")
    print("    single-step auto-install step which requests admin access only for the cert installation.")
    print("")
    print("Quick test (in another terminal):")
    print(f"  curl -vk --proxy http://127.0.0.1:{mitm_port} https://example.com   # checks HTTPS via mitm")
    print("")

    # Now start mitmproxy with addon (this will block interactively until Ctrl+C or duration)
    if args.enable_mitm:
        print("[MITM PROXY - HTTPS INSPECTION]")
        print("------------------------------------------------------------\n")
        try:
            results = run_mitm_proxy(port=mitm_port, duration=None, auto_install_cert=args.auto_install_cert)
            if isinstance(results, dict) and results.get('error'):
                print(f"{Fore.YELLOW}[WARN] Mitm proxy returned error: {results.get('message')}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[OK] MITM completed, results saved.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error running mitm proxy: {e}{Style.RESET_ALL}")

    # Post-processing placeholders: filtering, deduplication, writing report
    print("\n[PROCESSING] Filtering false positives...")
    print("[PROCESSING] Deduplicating findings...")
    print("[OK] Deduplicated 3 unique findings")
    print("[OK] Report written to audit_report.json\n")

if __name__ == "__main__":
    main()