#!/usr/bin/env python3
"""
Network scanner utilities used by local_check.py

- Proxy-aware HTTP client via get_proxied_session()
- ComprehensiveSecurityTester that uses the proxy session automatically
- Helper run_comprehensive_test() to drive active tests

Intended for local development / audit flows.
"""

import os
import sys
import re
import time
import json
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

def get_proxied_session(proxy_port=None, verify_cert=True, timeout=10):
    """
    Return a requests.Session configured to use a mitm proxy if present.

    - If proxy_port is provided, uses http://127.0.0.1:<proxy_port> for both http/https
    - Else, if HTTP_PROXY/http_proxy present in env, uses that
    - verify_cert controls TLS verification (dev-mode often uses False)
    """
    s = requests.Session()

    if proxy_port:
        proxy = f"http://127.0.0.1:{proxy_port}"
    else:
        proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')

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
# Active HTTP tester
# ------------------------------------------------------------------------------

class ComprehensiveSecurityTester:
    """
    Active security tester that probes a web application.

    - Authentication endpoint probing
    - CRUD read checks (GETs)
    - Missing security headers
    - Optional rate limit checks
    - Pattern scanning on URLs, headers, and bodies
    """

    def __init__(self, base_url, use_proxy=False, proxy_port=8080):
        self.base_url = base_url.rstrip('/')
        # Use proxy-aware session. In dev/proxy mode we usually disable TLS verification.
        self.session = get_proxied_session(
            proxy_port=(proxy_port if use_proxy else None),
            verify_cert=(not use_proxy)
        )
        self.findings = []
        self.request_log = []

    # --------------- utilities ---------------

    def log_finding(self, severity, category, description, details=None):
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details or ""
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
        if content is None:
            return
        text = str(content)

        # Network security patterns (regex)
        for name, cfg in NETWORK_SECURITY_PATTERNS.items():
            try:
                matches = cfg['pattern'].findall(text)
            except re.error:
                matches = []
            if matches:
                self.log_finding(
                    cfg['severity'], name, cfg['description'],
                    f"{context}: Found {len(matches)} occurrence(s)"
                )

        # Repo KNOWN_PATTERNS (single-match search)
        for name, pat in PATTERN_CONFIG.items():
            try:
                m = pat.search(text)
            except Exception:
                m = None
            if m:
                self.log_finding(
                    'HIGH',
                    f'secret_pattern_{name}',
                    f'Secret pattern detected: {name}',
                    f"{context}: {m.group(0)[:100]}"
                )

    # --------------- HTTP actions ---------------

    def test_endpoint(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"
        print(f"\n{Fore.CYAN}Testing: {method} {endpoint}{Style.RESET_ALL}")
        try:
            timeout = kwargs.pop('timeout', getattr(self.session, 'request_timeout', 10))
            resp = self.session.request(method, url, timeout=timeout, **kwargs)

            self.request_log.append({
                'method': method,
                'url': url,
                'status': resp.status_code,
                'timestamp': datetime.now().isoformat()
            })

            # Analyze request pieces we provided
            if 'data' in kwargs:
                self.analyze_content(kwargs['data'], f"Request body to {endpoint}")
            if 'json' in kwargs:
                self.analyze_content(json.dumps(kwargs['json']), f"Request JSON to {endpoint}")
            if 'headers' in kwargs:
                self.analyze_content(str(kwargs['headers']), f"Request headers to {endpoint}")

            # Analyze URL + response
            self.analyze_content(url, f"URL: {endpoint}")
            self.analyze_content(resp.text, f"Response from {endpoint}")
            self.analyze_content(str(resp.headers), f"Response headers from {endpoint}")

            # Security headers
            self.check_security_headers(resp, endpoint)

            # Warn on plaintext HTTP to non-local hosts
            if url.startswith('http://') and not url.startswith('http://localhost') and not url.startswith('http://127.0.0.1'):
                self.log_finding(
                    'HIGH',
                    'insecure_http',
                    'Using HTTP instead of HTTPS',
                    f'{endpoint} - Data transmitted in plaintext'
                )

            print(f"  Status: {resp.status_code}")
            return resp

        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
            return None

    def check_security_headers(self, response, endpoint):
        important = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': '1; mode=block'
        }
        for header, desc in important.items():
            if header not in response.headers:
                self.log_finding(
                    'LOW',
                    'missing_security_header',
                    f'Missing security header: {header}',
                    f'{endpoint} - Should include {desc}'
                )

    # --------------- test plan ---------------

    def run_tests(self, test_auth=True, test_crud=True, test_rate_limit=False):
        token = None

        # Auth probing
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
                resp = self.test_endpoint('POST', endpoint, json=login_data)
                if resp and resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                    except Exception:
                        data = None
                    if data and 'token' in str(data).lower():
                        print(f"  {Fore.GREEN}✓ Token-based auth detected{Style.RESET_ALL}")
                        token = data.get('token') or data.get('access_token')
                        break

        # Read-only CRUD checks (if we got a token)
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
                time.sleep(0.4)

        # Naive rate limit probe
        if test_rate_limit:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}RATE LIMITING TESTS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

            endpoint = '/api/login'
            print(f"Sending 10 rapid requests to {endpoint}...")

            rate_limited = False
            for i in range(10):
                resp = self.test_endpoint('POST', endpoint, json={'username': f'test{i}', 'password': 'test'})
                if resp and resp.status_code == 429:
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
        counts = defaultdict(int)
        for f in self.findings:
            counts[f['severity']] += 1
        return {
            'summary': dict(counts),
            'findings': self.findings,
            'requests': self.request_log,
            'total_requests': len(self.request_log),
            'total_findings': len(self.findings)
        }

# ------------------------------------------------------------------------------
# External entrypoint used by local_check.py
# ------------------------------------------------------------------------------

def run_comprehensive_test(
    target_url,
    enable_auth=True,
    enable_crud=True,
    enable_rate_limit=False,
    use_proxy=False,
    proxy_port=8080
):
    """
    Run the comprehensive tester and return its report dict.
    Designed to be called from local_check.py
    """
    print(f"\n{Fore.CYAN}Starting comprehensive security testing...{Style.RESET_ALL}")
    print(f"Target: {target_url}")

    tester = ComprehensiveSecurityTester(
        base_url=target_url,
        use_proxy=use_proxy,
        proxy_port=proxy_port
    )

    try:
        tester.run_tests(
            test_auth=enable_auth,
            test_crud=enable_crud,
            test_rate_limit=enable_rate_limit
        )
        report = tester.get_report()

        # Summary to console
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SECURITY TEST SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"Total requests: {report['total_requests']}")
        print(f"Total findings: {report['total_findings']}")

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            n = report['summary'].get(sev, 0)
            if n:
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.LIGHTRED_EX,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.LIGHTBLUE_EX,
                    'INFO': Fore.LIGHTBLACK_EX
                }[sev]
                print(f"  {color}{sev}: {n}{Style.RESET_ALL}")

        return report

    except Exception as e:
        print(f"{Fore.RED}Error during testing: {e}{Style.RESET_ALL}")
        return {
            "error": "comprehensive-test-failed",
            "exception": str(e),
            "message": "Comprehensive security testing failed"
        }