"""
Comprehensive Network Security Scanner
Combines passive packet capture with active security testing and MITM proxy inspection.

Features:
- Interactive packet capture (runs until Ctrl+C)
- MITM proxy for HTTPS traffic inspection (mitmproxy addon)
- Comprehensive HTTP/HTTPS security testing
- Pattern-based secret detection in network traffic
- Authentication, session, injection, and rate-limit testing

Dependencies:
    Required: requests
    Optional: scapy (for packet capture), mitmproxy (for HTTPS inspection), colorama (for colored output)
"""

import json
import re
import time
import sys
import os
import signal
import threading
import subprocess
import tempfile
from datetime import datetime
from collections import defaultdict
import asyncio

# Optional dependencies
USE_SCAPY = False
USE_MITMPROXY = False
USE_COLORAMA = False

try:
    from scapy.all import sniff, TCP, Raw, conf
    USE_SCAPY = True
except ImportError:
    USE_SCAPY = False

# Check if mitmdump is available (we run it as subprocess, so no import needed)
try:
    import shutil
    python_dir = os.path.dirname(sys.executable)
    
    # Check multiple possible locations
    possible_mitmdump_paths = [
        os.path.join(python_dir, 'mitmdump.exe'),  # Same dir as python
        os.path.join(python_dir, 'mitmdump'),  # Linux/Mac same dir
        os.path.join(os.path.dirname(python_dir), 'Scripts', 'mitmdump.exe'),  # Venv structure
    ]
    
    if shutil.which('mitmdump') or any(os.path.exists(p) for p in possible_mitmdump_paths):
        USE_MITMPROXY = True
except:
    USE_MITMPROXY = False

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init()
    USE_COLORAMA = True
except ImportError:
    # Fallback to no colors
    class Fore:
        RED = LIGHTRED_EX = YELLOW = LIGHTBLUE_EX = LIGHTBLACK_EX = GREEN = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""
    USE_COLORAMA = False

# Global list to collect captured packets
pcap_capture_results = []

# Global flag for stopping capture
_stop_capture = False

# Import patterns from config
from config import KNOWN_PATTERNS as PATTERN_CONFIG

# Additional patterns for network testing
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


def scapy_packet_callback(pkt):
    """
    Callback function for scapy packet capture.
    
    Analyzes TCP packets with raw data payload to detect HTTP requests/responses.
    Only captures plaintext HTTP (HTTPS payloads are encrypted and not visible).
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
    
    Returns:
        tuple: (has_privileges: bool, error_message: str or None)
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
    
    Args:
        timeout (int): Duration in seconds (None = run until Ctrl+C)
        filter_expr (str): Optional BPF filter expression
        use_l3 (bool): Use L3 socket (no Npcap required)
        
    Returns:
        dict: Result dictionary with captured count or error
    """
    global _stop_capture
    _stop_capture = False
    
    if not USE_SCAPY:
        return {
            "error": "scapy-not-installed",
            "message": "Install scapy with: pip install scapy"
        }
    
    # Check privileges
    has_privileges, error_msg = check_pcap_privileges()
    if not has_privileges:
        return {
            "error": "insufficient-privileges",
            "message": error_msg
        }
    
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}INTERACTIVE PACKET CAPTURE{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    if timeout:
        print(f"[*] Starting packet capture for {timeout}s...")
    else:
        print(f"[*] Starting interactive packet capture...")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop capture and continue scan{Style.RESET_ALL}")
    
    if sys.platform == "win32":
        if use_l3:
            print("    Using L3 socket capture (no Npcap required)")
        else:
            print("    Note: Ensure Npcap or WinPcap is installed on Windows")
    
    def signal_handler(sig, frame):
        global _stop_capture
        print(f"\n{Fore.YELLOW}[!] Stopping packet capture...{Style.RESET_ALL}")
        _stop_capture = True
    
    # Register signal handler for Ctrl+C
    original_handler = signal.signal(signal.SIGINT, signal_handler)
    
    try:
        start_time = time.time()
        
        def stop_filter(pkt):
            """Stop condition for sniff"""
            if _stop_capture:
                return True
            if timeout and (time.time() - start_time) > timeout:
                return True
            return False
        
        try:
            if use_l3:
                if filter_expr:
                    sniff(filter=filter_expr, prn=scapy_packet_callback, 
                         stop_filter=stop_filter, L2socket=conf.L3socket)
                else:
                    sniff(filter="tcp port 80 or tcp port 443", prn=scapy_packet_callback, 
                         stop_filter=stop_filter, L2socket=conf.L3socket)
            else:
                if filter_expr:
                    sniff(filter=filter_expr, prn=scapy_packet_callback, 
                         stop_filter=stop_filter)
                else:
                    sniff(filter="tcp port 80 or tcp port 443", prn=scapy_packet_callback, 
                         stop_filter=stop_filter)
        except Exception as e:
            err_str = str(e)
            if "winpcap" in err_str.lower() or "npcap" in err_str.lower():
                return {
                    "error": "pcap-failed",
                    "exception": err_str,
                    "message": "Packet capture failed: L2 capture unavailable (Npcap/WinPcap missing).",
                    "hint": "On Windows install Npcap (https://nmap.org/npcap/) or re-run with --pcap-layer3"
                }
            else:
                return {
                    "error": "pcap-failed",
                    "exception": err_str,
                    "message": "Packet capture failed. Check privileges and network adapter status.",
                    "hint": "Try running as Administrator or pass --pcap-layer3"
                }
    except PermissionError as e:
        return {
            "error": "permission-denied",
            "message": f"Permission denied during packet capture: {e}",
            "hint": "On Windows, ensure you're running as Administrator and Npcap is installed"
        }
    finally:
        # Restore original signal handler
        signal.signal(signal.SIGINT, original_handler)
    
    print(f"\n{Fore.GREEN}[OK] Captured {len(pcap_capture_results)} packets{Style.RESET_ALL}")
    return {"captured": len(pcap_capture_results)}


# ============================================================================
# MITMPROXY ADDON FOR HTTPS TRAFFIC INSPECTION
# ============================================================================

# Global storage for MITM captured traffic
mitm_capture_results = []

class SecurityInspectorAddon:
    """
    Mitmproxy addon for real-time HTTPS traffic inspection.
    
    Intercepts and analyzes all HTTP/HTTPS traffic passing through the proxy,
    detecting secrets, tokens, and security issues in both requests and responses.
    """
    
    def __init__(self):
        self.findings = []
        self.request_count = 0
        self.response_count = 0
    
    def request(self, flow: "http.HTTPFlow") -> None:
        """Inspect outgoing requests"""
        self.request_count += 1
        
        # Capture request details
        req_data = {
            'type': 'request',
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'timestamp': datetime.now().isoformat()
        }
        
        # Capture request body if present
        if flow.request.content:
            try:
                req_data['body'] = flow.request.content.decode('utf-8', errors='ignore')[:10000]
            except:
                req_data['body'] = '<binary data>'
        
        mitm_capture_results.append(req_data)
        
        # Analyze request for secrets
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
        """Inspect incoming responses"""
        self.response_count += 1
        
        # Capture response details
        resp_data = {
            'type': 'response',
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'timestamp': datetime.now().isoformat()
        }
        
        # Capture response body if present
        if flow.response.content:
            try:
                resp_data['body'] = flow.response.content.decode('utf-8', errors='ignore')[:10000]
            except:
                resp_data['body'] = '<binary data>'
        
        mitm_capture_results.append(resp_data)
        
        # Analyze response for secrets
        for key, value in flow.response.headers.items():
            self._analyze_content(f"{key}: {value}", f'Response Header ({key})', flow)
        
        if flow.response.content:
            try:
                content = flow.response.content.decode('utf-8', errors='ignore')
                self._analyze_content(content, 'Response Body', flow)
            except:
                pass
        
        # Check for security headers
        self._check_security_headers(flow)
    
    def _analyze_content(self, content: str, context: str, flow: "http.HTTPFlow"):
        """Analyze content for patterns"""
        if not content:
            return
        
        # Check network-specific patterns
        for name, config in NETWORK_SECURITY_PATTERNS.items():
            matches = config['pattern'].findall(content)
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
        
        # Check main patterns from config.py
        for name, pat in PATTERN_CONFIG.items():
            try:
                match = pat.search(content)
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
        """Check for missing security headers"""
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


def auto_install_mitm_cert(proxy_port=8080):
    """
    Automatically download and install mitmproxy certificate.
    Must be run as Administrator/root.
    
    Args:
        proxy_port (int): Port where mitmproxy is running (default: 8080)
        
    Returns:
        dict: Result with success status or error details
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
        if os.geteuid() != 0:
            print(f"{Fore.RED}  ✗ Root privileges required{Style.RESET_ALL}")
            return {
                "error": "insufficient-privileges",
                "message": "Run with sudo"
            }
        print(f"{Fore.GREEN}  ✓ Running as root{Style.RESET_ALL}")
    
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
    
    # Verify
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


def run_mitm_proxy(port=8080, duration=None, auto_install_cert=False):
    """
    Run mitmproxy with the SecurityInspectorAddon as a subprocess.
    
    Args:
        port (int): Port to run the proxy on (default: 8080)
        duration (int): Duration in seconds (None = run until Ctrl+C)
        auto_install_cert (bool): Automatically install certificate (requires admin/sudo)
        
    Returns:
        dict: Results with findings and captured traffic
    """
    if not USE_MITMPROXY:
        return {
            "error": "mitmproxy-not-installed",
            "message": "mitmproxy not available. Install with: pip install mitmproxy"
        }
    
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}MITMPROXY HTTPS TRAFFIC INSPECTION{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    # Auto-install certificate if requested
    if auto_install_cert:
        # First, start a temporary proxy to download cert
        print(f"\n{Fore.YELLOW}[INFO] Auto-installing certificate (requires admin/sudo)...{Style.RESET_ALL}")
        
        # Start temporary mitmdump for cert download
        temp_process = None
        try:
            # Find mitmdump
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
                except:
                    continue
            
            if mitmdump_cmd:
                # Start temporary proxy
                print(f"{Fore.CYAN}  Starting temporary proxy for cert download...{Style.RESET_ALL}")
                temp_process = subprocess.Popen(
                    [mitmdump_cmd, '-p', str(port), '--set', 'stream_large_bodies=1'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(2)  # Wait for proxy to start
                
                # Install certificate
                cert_result = auto_install_mitm_cert(proxy_port=port)
                
                # Stop temporary proxy
                temp_process.terminate()
                try:
                    temp_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    temp_process.kill()
                
                if "error" in cert_result:
                    print(f"{Fore.YELLOW}  ⚠ Auto-install failed: {cert_result.get('message')}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}  Continuing with manual certificate instructions...{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}  ⚠ Could not find mitmdump for auto-install{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.YELLOW}  ⚠ Auto-install error: {e}{Style.RESET_ALL}")
            if temp_process:
                try:
                    temp_process.kill()
                except:
                    pass
    
    if duration:
        print(f"\n[*] Starting mitmproxy on port {port} for {duration}s...")
    else:
        print(f"\n[*] Starting mitmproxy on port {port} (interactive mode)...")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop proxy and continue scan{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Configure your browser/application to use proxy:{Style.RESET_ALL}")
    print(f"  HTTP Proxy:  127.0.0.1:{port}")
    print(f"  HTTPS Proxy: 127.0.0.1:{port}")
    
    if not auto_install_cert:
        print(f"\n{Fore.CYAN}For HTTPS, install mitmproxy certificate:{Style.RESET_ALL}")
        print(f"  Option 1 (Browser):")
        print(f"    1. Set proxy in browser")
        print(f"    2. Visit: http://mitm.it")
        print(f"    3. Download and install certificate for your system")
        print(f"  Option 2 (Automated - requires admin/sudo):")
        print(f"    Run: python install_mitm_cert.py --port {port}")
    
    print(f"\n{Fore.YELLOW}Waiting for traffic...{Style.RESET_ALL}\n")
    
    # Create addon script file
    addon_script = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
    addon_script_path = addon_script.name
    
    # Convert patterns to string representation for the addon script
    patterns_str = "{\n"
    for name, config in NETWORK_SECURITY_PATTERNS.items():
        pattern_str = config['pattern'].pattern.replace('\\', '\\\\').replace("'", "\\'")
        patterns_str += f"    '{name}': {{\n"
        patterns_str += f"        'pattern': re.compile(r'''{pattern_str}'''),\n"
        patterns_str += f"        'severity': '{config['severity']}',\n"
        patterns_str += f"        'description': '{config['description']}'\n"
        patterns_str += f"    }},\n"
    patterns_str += "}"
    
    # Write the addon script
    addon_code = f'''
import json
import re
from datetime import datetime
from collections import defaultdict
from mitmproxy import http

# Pattern definitions
NETWORK_SECURITY_PATTERNS = {patterns_str}

# Results storage
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
        
        # Analyze for patterns
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
        if not content:
            return
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
            except Exception as e:
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
        # Write results to temp file
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
    
    # Start mitmproxy as subprocess
    results_file = os.path.join(tempfile.gettempdir(), 'mitm_results.json')
    if os.path.exists(results_file):
        os.remove(results_file)
    
    try:
        # Run mitmdump with the addon script
        # Try to find mitmdump executable
        mitmdump_cmd = None
        
        # First, try to find mitmdump in the same directory as python
        python_dir = os.path.dirname(sys.executable)
        possible_paths = [
            os.path.join(python_dir, 'mitmdump.exe'),  # Windows - same dir as python.exe
            os.path.join(python_dir, 'mitmdump'),  # Linux/Mac - same dir
            'mitmdump',  # In PATH
            'mitmdump.exe',  # In PATH (Windows)
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--version'], capture_output=True, timeout=2)
                if result.returncode == 0:
                    mitmdump_cmd = path
                    print(f"{Fore.GREEN}[INFO] Found mitmdump at: {path}{Style.RESET_ALL}")
                    break
            except:
                continue
        
        if not mitmdump_cmd:
            return {
                "error": "mitmproxy-not-found",
                "message": "Cannot find mitmdump executable. Install with: pip install mitmproxy",
                "hint": f"Tried: {', '.join(possible_paths)}"
            }
        
        # Build command
        cmd = [
            mitmdump_cmd,
            '-p', str(port),
            '-s', addon_script_path,
            '--set', 'stream_large_bodies=1'
        ]
        
        print(f"{Fore.YELLOW}[INFO] Starting mitmproxy subprocess...{Style.RESET_ALL}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Give it a moment to start
        time.sleep(2)
        
        # Check if process started successfully
        if process.poll() is not None:
            # Process already exited - error
            stdout, stderr = process.communicate()
            return {
                "error": "mitm-failed",
                "message": f"Mitmproxy failed to start. Error: {stderr}",
                "stdout": stdout
            }
        
        print(f"{Fore.GREEN}[OK] Mitmproxy is running!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}NOW: Configure your browser proxy and interact with your app{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Wait for duration or Ctrl+C
        try:
            if duration:
                print(f"{Fore.YELLOW}[INFO] Waiting {duration} seconds...{Style.RESET_ALL}")
                process.wait(timeout=duration)
            else:
                print(f"{Fore.YELLOW}[INFO] Proxy running... Press Ctrl+C when done testing{Style.RESET_ALL}")
                # Poll every second to allow keyboard interrupt
                while process.poll() is None:
                    time.sleep(1)
        except subprocess.TimeoutExpired:
            print(f"\n{Fore.YELLOW}[!] Timeout reached, stopping mitmproxy...{Style.RESET_ALL}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Ctrl+C detected, stopping mitmproxy...{Style.RESET_ALL}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        # Read results
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                results = json.load(f)
            os.remove(results_file)
        else:
            results = {
                "requests": 0,
                "responses": 0,
                "findings": [],
                "captured": 0,
                "severity_summary": {}
            }
        
        # Cleanup addon script
        try:
            os.remove(addon_script_path)
        except:
            pass
        
        # Display summary
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
        # Cleanup
        try:
            os.remove(addon_script_path)
        except:
            pass
        
        return {
            "error": "mitm-failed",
            "exception": str(e),
            "message": f"Mitmproxy failed to start: {e}"
        }


# ============================================================================
# COMPREHENSIVE SECURITY TESTING (Active Scanning)
# ============================================================================

class ComprehensiveSecurityTester:
    """
    Comprehensive security tester that actively probes a web application.
    
    Performs active security testing including:
    - Authentication endpoint testing
    - CRUD operation testing
    - Security header validation
    - Rate limiting checks
    """
    
    def __init__(self, base_url, use_proxy=False, proxy_port=8080):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.findings = []
        self.request_log = []
        
        # Configure session for proxy if requested
        if use_proxy:
            self.session.proxies = {
                'http': f'http://127.0.0.1:{proxy_port}',
                'https': f'http://127.0.0.1:{proxy_port}'
            }
            self.session.verify = False
        
        # Disable SSL warnings
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except:
            pass
    
    def log_finding(self, severity, category, description, details):
        """Log a security finding"""
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
        """Analyze content for security issues"""
        if not content:
            return
        
        content_str = str(content)
        
        # Check network-specific patterns
        for name, config in NETWORK_SECURITY_PATTERNS.items():
            matches = config['pattern'].findall(content_str)
            if matches:
                self.log_finding(
                    config['severity'],
                    name,
                    config['description'],
                    f"{context}: Found {len(matches)} occurrence(s)"
                )
        
        # Check main patterns from config.py
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
        """Test a single endpoint and analyze traffic"""
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
            
            # Analyze request
            if 'data' in kwargs:
                self.analyze_content(kwargs['data'], f"Request body to {endpoint}")
            if 'json' in kwargs:
                self.analyze_content(json.dumps(kwargs['json']), f"Request JSON to {endpoint}")
            if 'headers' in kwargs:
                self.analyze_content(str(kwargs['headers']), f"Request headers to {endpoint}")
            
            # Analyze URL
            self.analyze_content(url, f"URL: {endpoint}")
            
            # Analyze response
            self.analyze_content(response.text, f"Response from {endpoint}")
            self.analyze_content(str(response.headers), f"Response headers from {endpoint}")
            
            # Check security headers
            self.check_security_headers(response, endpoint)
            
            # Check HTTP vs HTTPS
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
        """Check for missing security headers"""
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
        """Run selected security tests"""
        token = None
        
        if test_auth:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}AUTHENTICATION TESTS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            
            login_data = {
                'username': 'testuser',
                'password': 'TestPassword123!',
                'email': 'test@example.com'
            }
            
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
                response = self.test_endpoint('POST', endpoint, 
                                            json={'username': f'test{i}', 'password': 'test'})
                if response and response.status_code == 429:
                    rate_limited = True
                    print(f"  {Fore.GREEN}✓ Rate limiting detected at request {i+1}{Style.RESET_ALL}")
                    break
                time.sleep(0.1)
            
            if not rate_limited:
                self.log_finding(
                    'MEDIUM',
                    'no_rate_limiting',
                    'No rate limiting detected',
                    f'Sent 10 requests to {endpoint} without being blocked'
                )
    
    def get_report(self):
        """Return findings as a structured report"""
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


def run_comprehensive_test(target_url, enable_auth=True, enable_crud=True, enable_rate_limit=False, use_proxy=False, proxy_port=8080):
    """
    Run comprehensive security testing on a target URL.
    Called by local_check.py when --enable-network-test is passed.
    
    Args:
        target_url (str): Base URL to test
        enable_auth (bool): Test authentication endpoints
        enable_crud (bool): Test CRUD operations
        enable_rate_limit (bool): Test rate limiting
        
    Returns:
        dict: Test results with findings and summary
    """
    print(f"\n{Fore.CYAN}Starting comprehensive security testing...{Style.RESET_ALL}")
    print(f"Target: {target_url}")
    
    tester = ComprehensiveSecurityTester(target_url, use_proxy=use_proxy, proxy_port=proxy_port)
    
    try:
        tester.run_tests(
            test_auth=enable_auth,
            test_crud=enable_crud,
            test_rate_limit=enable_rate_limit
        )
        
        report = tester.get_report()
        
        # Print summary
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SECURITY TEST SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"Total requests: {report['total_requests']}")
        print(f"Total findings: {report['total_findings']}")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if report['summary'].get(severity, 0) > 0:
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.LIGHTRED_EX,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.LIGHTBLUE_EX,
                    'INFO': Fore.LIGHTBLACK_EX
                }[severity]
                print(f"  {color}{severity}: {report['summary'][severity]}{Style.RESET_ALL}")
        
        return report
        
    except Exception as e:
        print(f"{Fore.RED}Error during testing: {e}{Style.RESET_ALL}")
        return {
            "error": "comprehensive-test-failed",
            "exception": str(e),
            "message": "Comprehensive security testing failed"
        }
