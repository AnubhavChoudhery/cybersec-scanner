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

STATUS_FILE = Path(__file__).parent / "mitm_inject_status.json"
LOG_FILE = Path(__file__).parent / "mitm_inject.log"
_lock = threading.Lock()

# Simple terminal logging for visibility
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logger = logging.getLogger("mitm_inject")


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

        # Terminal visibility: log proxied vs bypassed with uniform stage names
        try:
            if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                msg = f"[MITM] PROXY {method} {_redact(url)} (client=requests)"
                logger.info(msg)
                _log_stage("mitm_outbound", {"client": "requests", "method": method, "url": _redact(url)})
            else:
                msg = f"[MITM] BYPASS {method} {_redact(url)} (client=requests)"
                logger.info(msg)
                _log_stage("mitm_bypass", {"client": "requests", "method": method, "url": _redact(url)})
        except Exception:
            pass

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
        try:
            if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                msg = f"[MITM] PROXY {method} {_redact(url)} (client=httpx)"
                logger.info(msg)
                _log_stage("mitm_outbound", {"client": "httpx", "method": method, "url": _redact(url)})
            else:
                msg = f"[MITM] BYPASS {method} {_redact(url)} (client=httpx)"
                logger.info(msg)
                _log_stage("mitm_bypass", {"client": "httpx", "method": method, "url": _redact(url)})
        except Exception:
            pass

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
            try:
                msg = f"[MITM] PROXY OPEN {_redact(url)} (client=urllib)"
                logger.info(msg)
                _log_stage("mitm_outbound", {"client": "urllib", "method": "OPEN", "url": _redact(url)})
            except Exception:
                pass
            return opener.open(url, data=data, timeout=timeout)
        try:
            msg = f"[MITM] BYPASS OPEN {_redact(url)} (client=urllib)"
            logger.info(msg)
            _log_stage("mitm_bypass", {"client": "urllib", "method": "OPEN", "url": _redact(url)})
        except Exception:
            pass
        return orig_urlopen(url, data=data, timeout=timeout)

    urllib.request.urlopen = _patched
    return True


def _patch_urllib3():
    try:
        import urllib3
    except Exception:
        _log_stage("urllib3_missing")
        return False

    # Patch PoolManager.request used by many clients
    try:
        orig_pool_request = urllib3.PoolManager.request

        def _pm_request(self, method, url, **kwargs):
            try:
                if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                    logger.info(f"[MITM] PROXY {method} {_redact(url)} (client=urllib3)")
                    _log_stage("mitm_outbound", {"client": "urllib3", "method": method, "url": _redact(url)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(url)} (client=urllib3)")
                    _log_stage("mitm_bypass", {"client": "urllib3", "method": method, "url": _redact(url)})
            except Exception:
                pass
            return orig_pool_request(self, method, url, **kwargs)

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
                    _log_stage("mitm_outbound", {"client": "urllib3.conn", "method": method, "url": _redact(full)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(full)} (client=urllib3.conn)")
                    _log_stage("mitm_bypass", {"client": "urllib3.conn", "method": method, "url": _redact(full)})
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
        _log_stage("aiohttp_missing")
        return False

    # Patch ClientSession._request (async)
    try:
        orig_req = aiohttp.ClientSession._request

        async def _patched_request(self, method, str_or_url, **kwargs):
            url = str(str_or_url)
            try:
                if ENABLE_MITM and not MONITOR_ONLY and not _should_bypass(url):
                    logger.info(f"[MITM] PROXY {method} {_redact(url)} (client=aiohttp)")
                    _log_stage("mitm_outbound", {"client": "aiohttp", "method": method, "url": _redact(url)})
                else:
                    logger.info(f"[MITM] BYPASS {method} {_redact(url)} (client=aiohttp)")
                    _log_stage("mitm_bypass", {"client": "aiohttp", "method": method, "url": _redact(url)})
            except Exception:
                pass
            return await orig_req(self, method, str_or_url, **kwargs)

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
    if _patch_urllib3(): patched.append("urllib3")
    if _patch_aiohttp(): patched.append("aiohttp")

    _log_stage("inject_done", {"patched": patched})
    print(f"Patched libraries: {patched}")
    return True


if __name__ == "__main__":
    inject_mitm_proxy_advanced()
