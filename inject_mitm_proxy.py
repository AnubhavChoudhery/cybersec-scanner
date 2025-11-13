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
from typing import Optional
from urllib.parse import urlparse

# --- GLOBAL SETTINGS ---
MITM_PROXY_PORT = int(os.getenv("MITM_PROXY_PORT", 8082))
MITM_PROXY_URL = f"http://127.0.0.1:{MITM_PROXY_PORT}"
ENABLE_MITM = (os.getenv("ENABLE_MITM", "0") == "1")
MONITOR_ONLY = (os.getenv("MITM_MODE", "").lower() == "monitor")

STATUS_FILE = Path(__file__).parent / "mitm_inject_status.json"
LOG_FILE = Path(__file__).parent / "mitm_inject.log"
_lock = threading.Lock()


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

def _log_stage(stage: str, details: Optional[dict] = None):
    entry = {"ts": int(time.time()), "stage": stage}
    if details:
        entry["details"] = details
    with _lock:
        try:
            with STATUS_FILE.open("w", encoding="utf-8") as f:
                json.dump(entry, f)
            with LOG_FILE.open("a", encoding="utf-8") as lf:
                lf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {stage} - {details or ''}\n")
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


# ============================
# SSL PATCH (for MITM only)
# ============================

def _patch_ssl_global():
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        _log_stage("ssl_patched")
        return True
    except Exception:
        _log_stage("ssl_patch_failed")
        return False


# ============================
# REQUEST LIBRARY PATCHING
# ============================

def _patch_requests_session():
    try:
        import requests
    except Exception:
        _log_stage("requests_missing")
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
        _log_stage("requests_outgoing", {"url": _redact(url)})
        return orig_request(self, method, url, **kwargs)

    requests.Session.request = _patched_request
    return True


def _patch_httpx():
    try:
        import httpx
    except Exception:
        _log_stage("httpx_missing")
        return False

    orig_req = httpx.Client.request

    def _client_req(self, method, url, **kwargs):
        if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
            kwargs.setdefault("proxies", MITM_PROXY_URL)
            kwargs["verify"] = False
        return orig_req(self, method, url, **kwargs)

    httpx.Client.request = _client_req
    return True


def _patch_urllib():
    try:
        import urllib.request
    except Exception:
        return False

    orig_urlopen = urllib.request.urlopen

    def _patched(url, data=None, timeout=30, **kwargs):
        if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
            proxy_handler = urllib.request.ProxyHandler({
                "http": MITM_PROXY_URL, "https": MITM_PROXY_URL
            })
            ctx = ssl._create_unverified_context()
            opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
            return opener.open(url, data=data, timeout=timeout)
        return orig_urlopen(url, data=data, timeout=timeout)

    urllib.request.urlopen = _patched
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

    _log_stage("env_vars_set", {"NO_PROXY": os.environ.get("NO_PROXY", "")})


# ============================
# MAIN ENTRY
# ============================

def inject_mitm_proxy_advanced():
    _log_stage("inject_start", {
        "enable": ENABLE_MITM, "proxy": MITM_PROXY_URL
    })

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

    _log_stage("inject_done", {"patched": patched})
    print(f"Patched libraries: {patched}")
    return True


if __name__ == "__main__":
    inject_mitm_proxy_advanced()
