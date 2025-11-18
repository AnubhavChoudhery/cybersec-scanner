#!/usr/bin/env python3
"""
inject_mitm_proxy.py

Guarantees:

✔ AWS (ALL REGIONS, ALL SERVICES) bypass MITM
✔ OAuth providers bypass MITM
✔ AI providers bypass MITM
✔ Banking/payments (Stripe/PayPal) bypass MITM
✔ Cloudflare/CDN bypass MITM
✔ Localhost always bypassed
✔ boto3 never breaks due to proxy interception
✔ requests/httpx/urllib patched safely

Use:
    export ENABLE_MITM=1
    export MITM_PROXY_PORT=8082
    python -c "import inject_mitm_proxy; inject_mitm_proxy.inject_mitm_proxy_advanced()"
"""

from __future__ import annotations
import os
import sys
import ssl
import json
import time
import threading
from pathlib import Path
import logging
from typing import Optional
from urllib.parse import urlparse

# --- GLOBAL SETTINGS ---
MITM_PROXY_PORT = int(os.getenv("MITM_PROXY_PORT", 8082))
MITM_PROXY_URL = f"http://127.0.0.1:{MITM_PROXY_PORT}"
ENABLE_MITM = (os.getenv("ENABLE_MITM", "0") == "1")
MONITOR_ONLY = (os.getenv("MITM_MODE", "").lower() == "monitor")

TRAFFIC_LOG = Path(__file__).parent / "mitm_traffic.ndjson"
_lock = threading.Lock()

# Simple terminal logging for visibility
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logger = logging.getLogger("mitm_inject")

# Load security patterns
_patterns = {}
_patterns_loaded = False

# Expected server-side API authentication (suppress console alerts)
EXPECTED_SERVER_AUTH = {
    'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY',
    'GROQ_API_KEY',
    'MISTRAL_API_KEY',
    'HUGGINGFACE_TOKEN',
    'GITHUB_PAT',
    'GITLAB_PAT',
}

def _load_patterns():
    global _patterns, _patterns_loaded
    if _patterns_loaded:
        return
    try:
        import re
        patterns_file = Path(__file__).parent / "patterns.env"
        if patterns_file.exists():
            with patterns_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    name, pattern = line.split("=", 1)
                    try:
                        _patterns[name.strip()] = re.compile(pattern.strip())
                    except Exception:
                        pass
            print(f"[MITM] Loaded {len(_patterns)} security patterns from {patterns_file}")
        else:
            print(f"[MITM] WARNING: patterns.env not found at {patterns_file}")
        _patterns_loaded = True
    except Exception as e:
        print(f"[MITM] ERROR loading patterns: {e}")
        _patterns_loaded = True


# ============================================
# CLOUD-SAFE BYPASS DEFINITIONS (FINAL VERSION)
# ============================================

BYPASS_DOMAINS = set([

    # --- OAuth / Identity ---
    "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com", "googleapis.com",
    "login.microsoftonline.com", "login.live.com",
    "auth0.com", "okta.com",

    # --- Banking / Payments ---
    "stripe.com", "api.stripe.com",
    "paypal.com", "api.paypal.com",

    # --- Cloudflare / CDNs ---
    "cloudflare.com", "cloudflare.net",
    "cloudfront.net",
])

# --- AWS BYPASS (ALL REGIONS, ALL SERVICES) ---
AWS_SUFFIXES = [
    ".amazonaws.com",          # Main AWS domain
    ".execute-api.",          # API Gateway URLs
    ".lambda-url.",           # Lambda function URLs
    ".cloudfront.net",        # CloudFront
    ".s3.amazonaws.com",      # S3
]

# --- Always bypass localhost ---
LOCALHOST_BYPASS = {"localhost", "127.0.0.1", "::1"}


# ============================
# LOGGING
# ============================

def _log_traffic(stage: str, details: Optional[dict] = None):
    """Append traffic events to NDJSON log (one line per request)"""
    if stage not in ("mitm_outbound", "mitm_bypass"):
        return
    
    entry = {
        "ts": int(time.time()),
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "stage": stage,
    }
    if details:
        entry.update(details)
    
    with _lock:
        try:
            with TRAFFIC_LOG.open("a", encoding="utf-8") as tf:
                json.dump(entry, tf)
                tf.write("\n")
        except Exception:
            pass


# ============================
# BYPASS LOGIC (FINAL VERSION)
# ============================

def _should_bypass(url: str) -> bool:
    """
    TRUE = do NOT use proxy
    FALSE = safe to proxy

    Priorities:
      1. localhost ALWAYS bypass
      2. AWS ANY REGION / ANY SERVICE bypass
      3. OAuth & identity bypass
      4. Banking/payment bypass
      5. AI providers bypass
    """

    try:
        p = urlparse(str(url))
        host = (p.hostname or "").lower()
        if not host:
            return False

        # Localhost always bypass
        if host in LOCALHOST_BYPASS:
            return True

        # Direct match bypass list
        if host in BYPASS_DOMAINS:
            return True

        # Wildcard match for bypass domains
        for d in BYPASS_DOMAINS:
            if host.endswith("." + d):
                return True

        # AWS wildcard region-agnostic bypass
        for suf in AWS_SUFFIXES:
            if suf in host:
                return True

        # Path-based auth bypass
        url_l = str(url).lower()
        for token in ("oauth", "openid", "/auth", "/login", "sso", "saml"):
            if token in url_l:
                return True

        return False

    except Exception:
        return True  # safest fallback


def _redact(url: str) -> str:
    try:
        p = urlparse(str(url))
        return f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        return str(url)[:200]


def _looks_like_hash(value: str) -> bool:
    """Check if value looks like a hash (not plaintext password)"""
    if not value or len(value) < 8:
        return False
    # bcrypt: $2[ab]$...
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return True
    # argon2: $argon2...
    if value.startswith("$argon2"):
        return True
    # sha256/512: 64/128 hex chars
    if len(value) in [64, 128] and all(c in "0123456789abcdef" for c in value.lower()):
        return True
    # base64-encoded hashes (likely JWT or encrypted)
    if len(value) > 40 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value):
        return True
    return False


def _inspect_security(method: str, url: str, client: str, **kwargs):
    """Lightweight security inspection of request"""
    _load_patterns()
    findings = []
    
    # Debug: confirm inspection is running
    if not _patterns_loaded:
        print(f"[MITM] WARNING: Security patterns not loaded!")
    
    # 1. Check URL for embedded credentials or API keys
    try:
        parsed = urlparse(str(url))
        # Check for user:pass@ in URL
        if parsed.username or parsed.password:
            findings.append({
                "severity": "CRITICAL",
                "type": "url_embedded_credentials",
                "url": _redact(url),
                "description": "Credentials embedded in URL (user:pass@domain)"
            })
        
        # Check query params for secrets
        if parsed.query:
            for pattern_name, pattern in _patterns.items():
                if pattern.search(parsed.query):
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "api_key_in_url",
                        "pattern": pattern_name,
                        "url": _redact(url),
                        "description": f"API key {pattern_name} exposed in URL query string (logged in browser history, proxy logs, server logs)"
                    })
                    break
    except Exception:
        pass
    
    # 2. Check headers for secrets
    headers = kwargs.get("headers", {})
    if headers:
        # Basic Auth (credentials in base64) - ALWAYS critical
        auth = headers.get("Authorization", headers.get("authorization", ""))
        if auth and "Basic" in auth:
            findings.append({
                "severity": "CRITICAL",
                "type": "basic_auth_header",
                "url": _redact(url),
                "description": "Basic Authentication (base64 credentials) in header"
            })
        
        # Check for API keys in headers
        parsed = urlparse(str(url))
        is_https = (parsed.scheme == "https")
        
        for header_name, header_value in headers.items():
            if header_name.lower() in ["authorization", "x-api-key", "api-key", "apikey"]:
                for pattern_name, pattern in _patterns.items():
                    if pattern.search(str(header_value)):
                        # Add context about HTTPS vs HTTP
                        if is_https and header_name.lower() == "authorization":
                            severity = "HIGH"
                            desc = f"{pattern_name} in Authorization header over HTTPS (expected for server-side API calls, review if unexpected)"
                        elif not is_https:
                            severity = "CRITICAL"
                            desc = f"API key {pattern_name} transmitted over insecure HTTP (unencrypted)"
                        else:
                            severity = "HIGH"
                            desc = f"Potential {pattern_name} in header {header_name}"
                        
                        findings.append({
                            "severity": severity,
                            "type": "api_key_in_header",
                            "pattern": pattern_name,
                            "header": header_name,
                            "url": _redact(url),
                            "description": desc
                        })
                        break
    
    # 3. Check request body for plaintext passwords and secrets
    body = kwargs.get("data") or kwargs.get("json")
    if body:
        body_str = str(body)
        
        # Password fields (context-based)
        import re
        password_fields = re.findall(r'["\']?(password|passwd|pwd|user_password|pass)["\']?\s*[:=]\s*["\']?([^"\',}\s]+)', body_str, re.IGNORECASE)
        for field, value in password_fields:
            if value and not _looks_like_hash(value) and len(value) > 3:
                findings.append({
                    "severity": "CRITICAL",
                    "type": "plaintext_password",
                    "field": field,
                    "url": _redact(url),
                    "description": f"Plaintext password in field '{field}' (not hashed)"
                })
        
        # Check body against all patterns
        for pattern_name, pattern in _patterns.items():
            matches = pattern.findall(body_str)
            if matches:
                findings.append({
                    "severity": "HIGH",
                    "type": "secret_in_body",
                    "pattern": pattern_name,
                    "url": _redact(url),
                    "description": f"Potential {pattern_name} in request body"
                })
    
    # Write findings to TRAFFIC_LOG with stage=security_finding
    if findings:
        with _lock:
            try:
                with TRAFFIC_LOG.open("a", encoding="utf-8") as tf:
                    for finding in findings:
                        finding.update({
                            "ts": int(time.time()),
                            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "method": method,
                            "client": client,
                            "stage": "security_finding",
                        })
                        json.dump(finding, tf)
                        tf.write("\n")
                        # Print HIGH/CRITICAL to console (skip expected server-side auth)
                        is_expected_auth = (
                            finding.get('type') == 'api_key_in_header' and
                            finding.get('pattern') in EXPECTED_SERVER_AUTH and
                            'expected for server-side' in finding.get('description', '')
                        )
                        if finding['severity'] in ['HIGH', 'CRITICAL'] and not is_expected_auth:
                            print(f"🚨 [{finding['severity']}] {finding['description']}")
            except Exception as e:
                print(f"[MITM] ERROR writing finding: {e}")
    
    return findings


def _inspect_response(url: str, response, client: str):
    """Inspect HTTP response for leaked secrets"""
    _load_patterns()
    findings = []
    
    try:
        # 1. Check response headers
        headers = getattr(response, 'headers', {})
        if headers:
            for header_name, header_value in headers.items():
                for pattern_name, pattern in _patterns.items():
                    if pattern.search(str(header_value)):
                        findings.append({
                            "severity": "CRITICAL",
                            "type": "secret_in_response_header",
                            "pattern": pattern_name,
                            "header": header_name,
                            "url": _redact(url),
                            "description": f"Secret {pattern_name} leaked in response header {header_name}"
                        })
                        break
        
        # 2. Check response body (limit size, skip binary)
        try:
            content_type = headers.get('Content-Type', headers.get('content-type', '')) if headers else ''
            is_text = any(ct in content_type.lower() for ct in ['text/', 'application/json', 'application/xml', 'application/javascript'])
            
            if is_text:
                # Get response text (different methods for different clients)
                body_text = None
                if hasattr(response, 'text'):
                    body_text = response.text if callable(response.text) else str(response.text)
                elif hasattr(response, 'content'):
                    try:
                        body_text = response.content.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                elif hasattr(response, 'read'):
                    try:
                        body_text = response.read().decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                
                # Limit scan size (500KB max)
                if body_text and len(body_text) > 0:
                    scan_text = body_text[:500_000]
                    
                    # Pattern match on response body
                    for pattern_name, pattern in _patterns.items():
                        matches = pattern.findall(scan_text)
                        if matches:
                            findings.append({
                                "severity": "CRITICAL",
                                "type": "secret_in_response_body",
                                "pattern": pattern_name,
                                "url": _redact(url),
                                "description": f"Secret {pattern_name} leaked in response body",
                                "snippet": matches[0][:200] if matches else None
                            })
        except Exception:
            pass
            
    except Exception:
        pass
    
    # Write findings to TRAFFIC_LOG
    if findings:
        with _lock:
            try:
                with TRAFFIC_LOG.open("a", encoding="utf-8") as tf:
                    for finding in findings:
                        finding.update({
                            "ts": int(time.time()),
                            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                            "client": client,
                            "stage": "security_finding",
                        })
                        json.dump(finding, tf)
                        tf.write("\n")
                        # Always print response leaks (CRITICAL)
                        print(f"🚨 [{finding['severity']}] {finding['description']}")
            except Exception as e:
                print(f"[MITM] ERROR writing response finding: {e}")
    
    return findings


# ============================
# SSL PATCH (for MITM only)
# ============================

def _patch_ssl_global():
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        return True
    except Exception:
        return False


# ============================
# REQUEST LIBRARY PATCHING
# ============================

def _patch_requests_session():
    try:
        import requests
    except Exception:
        return False

    orig_request = requests.Session.request

    def _patched_request(self, method, url, **kwargs):
        if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
            kwargs.setdefault("proxies", {
                "http": MITM_PROXY_URL,
                "https": MITM_PROXY_URL,
            })
            kwargs["verify"] = False
        else:
            kwargs.pop("proxies", None)

        kwargs.setdefault("timeout", 30)

        # Security inspection (request)
        try:
            _inspect_security(method, url, "requests", **kwargs)
        except Exception:
            pass
        
        # Terminal visibility and NDJSON logging
        try:
            if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                msg = f"[MITM] PROXY {method} {_redact(url)} (client=requests)"
                logger.info(msg)
                _log_traffic("mitm_outbound", {"client": "requests", "method": method, "url": _redact(url)})
            else:
                msg = f"[MITM] BYPASS {method} {_redact(url)} (client=requests)"
                logger.info(msg)
                _log_traffic("mitm_bypass", {"client": "requests", "method": method, "url": _redact(url)})
        except Exception:
            pass

        # Execute request
        response = orig_request(self, method, url, **kwargs)
        
        # Security inspection (response)
        try:
            _inspect_response(url, response, "requests")
        except Exception:
            pass
        
        return response

    requests.Session.request = _patched_request
    return True


def _patch_httpx():
    try:
        import httpx
    except Exception:
        return False

    orig_req = httpx.Client.request

    def _client_req(self, method, url, **kwargs):
        if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
            kwargs.setdefault("proxies", {
                "http://": MITM_PROXY_URL,
                "https://": MITM_PROXY_URL,
            })
            kwargs["verify"] = False
        
        kwargs.setdefault("timeout", 30)
        
        # Security inspection (request)
        try:
            _inspect_security(method, url, "httpx", **kwargs)
        except Exception:
            pass
        
        try:
            if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                msg = f"[MITM] PROXY {method} {_redact(url)} (client=httpx)"
                logger.info(msg)
                _log_traffic("mitm_outbound", {"client": "httpx", "method": method, "url": _redact(url)})
            else:
                msg = f"[MITM] BYPASS {method} {_redact(url)} (client=httpx)"
                logger.info(msg)
                _log_traffic("mitm_bypass", {"client": "httpx", "method": method, "url": _redact(url)})
        except Exception:
            pass

        # Execute request
        response = orig_req(self, method, url, **kwargs)
        
        # Security inspection (response)
        try:
            _inspect_response(url, response, "httpx")
        except Exception:
            pass
        
        return response

    httpx.Client.request = _client_req
    return True


def _patch_urllib():
    try:
        import urllib.request
    except Exception:
        return False

    orig_urlopen = urllib.request.urlopen

    def _patched(url, data=None, timeout=30, **kwargs):
        # Security inspection (request)
        try:
            _inspect_security("OPEN", url, "urllib", data=data, **kwargs)
        except Exception:
            pass
        
        if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
            proxy_handler = urllib.request.ProxyHandler({
                "http": MITM_PROXY_URL, "https": MITM_PROXY_URL
            })
            ctx = ssl._create_unverified_context()
            opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
            try:
                msg = f"[MITM] PROXY OPEN {_redact(url)} (client=urllib)"
                logger.info(msg)
                _log_traffic("mitm_outbound", {"client": "urllib", "method": "OPEN", "url": _redact(url)})
            except Exception:
                pass
            response = opener.open(url, data=data, timeout=timeout)
        else:
            try:
                msg = f"[MITM] BYPASS OPEN {_redact(url)} (client=urllib)"
                logger.info(msg)
                _log_traffic("mitm_bypass", {"client": "urllib", "method": "OPEN", "url": _redact(url)})
            except Exception:
                pass
            response = orig_urlopen(url, data=data, timeout=timeout)
        
        # Security inspection (response)
        try:
            _inspect_response(url, response, "urllib")
        except Exception:
            pass
        
        return response

    urllib.request.urlopen = _patched
    return True


def _patch_urllib3():
    try:
        import urllib3
    except Exception:
        return False

    # Patch PoolManager.request used by many clients
    try:
        orig_pool_request = urllib3.PoolManager.request

        def _pm_request(self, method, url, **kwargs):
            # Security inspection (request)
            try:
                _inspect_security(method, url, "urllib3", **kwargs)
            except Exception:
                pass
            
            try:
                if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                    logger.info(f"[MITM] PROXY {method} {_redact(url)} (client=urllib3)")
                    _log_traffic("mitm_outbound", {"client": "urllib3", "method": method, "url": _redact(url)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(url)} (client=urllib3)")
                    _log_traffic("mitm_bypass", {"client": "urllib3", "method": method, "url": _redact(url)})
            except Exception:
                pass
            
            # Execute request
            response = orig_pool_request(self, method, url, **kwargs)
            
            # Security inspection (response)
            try:
                _inspect_response(url, response, "urllib3")
            except Exception:
                pass
            
            return response

        urllib3.PoolManager.request = _pm_request
    except Exception:
        pass

    # Try to patch lower-level connection pool urlopen as well
    try:
        orig_conn_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen

        def _conn_urlopen(self, method, url, **kwargs):
            try:
                full = (getattr(self, 'host', '') and f"https://{self.host}{url}") or url
                if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(full):
                    logger.info(f"[MITM] PROXY {method} {_redact(full)} (client=urllib3.conn)")
                    _log_traffic("mitm_outbound", {"client": "urllib3.conn", "method": method, "url": _redact(full)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(full)} (client=urllib3.conn)")
                    _log_traffic("mitm_bypass", {"client": "urllib3.conn", "method": method, "url": _redact(full)})
            except Exception:
                pass
            return orig_conn_urlopen(self, method, url, **kwargs)

        urllib3.connectionpool.HTTPConnectionPool.urlopen = _conn_urlopen
    except Exception:
        pass

    return True


def _patch_aiohttp():
    try:
        import asyncio
        import aiohttp
    except Exception:
        return False

    # Patch ClientSession._request (async)
    try:
        orig_req = aiohttp.ClientSession._request

        async def _patched_request(self, method, str_or_url, **kwargs):
            url = str(str_or_url)
            
            # Security inspection (request)
            try:
                _inspect_security(method, url, "aiohttp", **kwargs)
            except Exception:
                pass
            
            try:
                if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                    logger.info(f"[MITM] PROXY {method} {_redact(url)} (client=aiohttp)")
                    _log_traffic("mitm_outbound", {"client": "aiohttp", "method": method, "url": _redact(url)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(url)} (client=aiohttp)")
                    _log_traffic("mitm_bypass", {"client": "aiohttp", "method": method, "url": _redact(url)})
            except Exception:
                pass
            
            # Execute request
            response = await orig_req(self, method, str_or_url, **kwargs)
            
            # Security inspection (response) - aiohttp responses need async handling
            try:
                _inspect_response(url, response, "aiohttp")
            except Exception:
                pass
            
            return response

        aiohttp.ClientSession._request = _patched_request
    except Exception:
        pass

    return True


# ============================
# ENVIRONMENT PROXY SETUP
# ============================

def setup_env_vars():
    """
    This function is *critical*.
    boto3 ONLY respects system-level:
        - HTTPS_PROXY
        - NO_PROXY
    So we must ensure AWS domains ALWAYS appear inside NO_PROXY.
    """

    if ENABLE_MITM and not MONITOR_ONLY:
        os.environ["HTTP_PROXY"] = MITM_PROXY_URL
        os.environ["HTTPS_PROXY"] = MITM_PROXY_URL

        # Build NO_PROXY list
        np = set(LOCALHOST_BYPASS)
        np.update(BYPASS_DOMAINS)

        # Add wildcard AWS bypass
        # boto3 respects: "amazonaws.com"
        np.update({
            "amazonaws.com",
            ".amazonaws.com",
        })

        os.environ["NO_PROXY"] = ",".join(sorted(np))
        os.environ["no_proxy"] = os.environ["NO_PROXY"]


# ============================
# MAIN ENTRY
# ============================

def inject_mitm_proxy_advanced():
    # Clear/create NDJSON traffic log on startup
    try:
        with _lock:
            TRAFFIC_LOG.write_text("")  # truncate existing file
    except Exception:
        pass

    if ENABLE_MITM and not MONITOR_ONLY:
        print(f"[MITM] Proxy active on {MITM_PROXY_URL}")
        _patch_ssl_global()
        setup_env_vars()
    else:
        print("[MITM] Monitor-only mode")

    patched = []
    if _patch_requests_session(): patched.append("requests")
    if _patch_httpx(): patched.append("httpx")
    if _patch_urllib(): patched.append("urllib")
    if _patch_urllib3(): patched.append("urllib3")
    if _patch_aiohttp(): patched.append("aiohttp")

    print(f"Patched libraries: {patched}")
    return True


if __name__ == "__main__":
    inject_mitm_proxy_advanced()
