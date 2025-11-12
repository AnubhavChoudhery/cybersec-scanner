"""
Advanced MITM Proxy injector - Patches HTTP libraries at runtime
This version directly patches requests, httpx, urllib to use the proxy
Works even when environment variables don't!

Usage Option 1 - Import at top of main file (EASIEST):
  # Very first line in your app.py/main.py
  import inject_mitm_proxy_advanced
  
Usage Option 2 - Conditional import (only when testing):
  if os.getenv('ENABLE_MITM'):
      import inject_mitm_proxy_advanced

Usage Option 3 - Use sitecustomize.py (automatic for all Python processes):
  Copy this to: backend/.venv/Lib/site-packages/sitecustomize.py
"""
import os
import sys
import warnings

# Configuration
MITM_PROXY_PORT = 8082
MITM_PROXY_URL = f"http://127.0.0.1:{MITM_PROXY_PORT}"

def patch_requests():
    """Patch the requests library to use MITM proxy"""
    try:
        import requests
        from requests.adapters import HTTPAdapter
        
        # Monkey-patch requests.Session to always use proxy
        original_init = requests.Session.__init__
        
        def patched_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            self.proxies = {
                'http': MITM_PROXY_URL,
                'https': MITM_PROXY_URL,
            }
            self.verify = False  # Disable SSL verification
        
        requests.Session.__init__ = patched_init
        
        # Also patch the default session
        requests.Session().proxies = {
            'http': MITM_PROXY_URL,
            'https': MITM_PROXY_URL,
        }
        
        print("✅ Patched: requests library")
        return True
    except ImportError:
        return False

def patch_httpx():
    """Patch the httpx library to use MITM proxy"""
    try:
        import httpx
        
        # Monkey-patch httpx.Client
        original_client_init = httpx.Client.__init__
        
        def patched_client_init(self, *args, **kwargs):
            kwargs['proxies'] = MITM_PROXY_URL
            kwargs['verify'] = False
            original_client_init(self, *args, **kwargs)
        
        httpx.Client.__init__ = patched_client_init
        
        # Patch AsyncClient too
        original_async_client_init = httpx.AsyncClient.__init__
        
        def patched_async_client_init(self, *args, **kwargs):
            kwargs['proxies'] = MITM_PROXY_URL
            kwargs['verify'] = False
            original_async_client_init(self, *args, **kwargs)
        
        httpx.AsyncClient.__init__ = patched_async_client_init
        
        print("✅ Patched: httpx library")
        return True
    except ImportError:
        return False

def patch_urllib():
    """Patch urllib to use MITM proxy"""
    try:
        import urllib.request
        
        # Install a global proxy handler
        proxy_handler = urllib.request.ProxyHandler({
            'http': MITM_PROXY_URL,
            'https': MITM_PROXY_URL,
        })
        
        # Create opener with proxy
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        
        print("✅ Patched: urllib library")
        return True
    except Exception:
        return False

def setup_environment():
    """Set environment variables as fallback"""
    os.environ['HTTP_PROXY'] = MITM_PROXY_URL
    os.environ['HTTPS_PROXY'] = MITM_PROXY_URL
    os.environ['http_proxy'] = MITM_PROXY_URL
    os.environ['https_proxy'] = MITM_PROXY_URL
    os.environ['NO_PROXY'] = ''
    os.environ['no_proxy'] = ''
    os.environ['REQUESTS_CA_BUNDLE'] = ''
    os.environ['CURL_CA_BUNDLE'] = ''
    os.environ['SSL_CERT_FILE'] = ''
    os.environ['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
    os.environ['PYTHONHTTPSVERIFY'] = '0'
    
    # Suppress warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

def inject_mitm_proxy_advanced():
    """Main injection function"""
    print()
    print("=" * 70)
    print("🔌 MITM PROXY ADVANCED INJECTION")
    print("=" * 70)
    print(f"Proxy URL: {MITM_PROXY_URL}")
    print()
    
    # Set environment variables
    setup_environment()
    print("✅ Environment variables set")
    
    # Patch HTTP libraries
    patched = []
    if patch_requests():
        patched.append("requests")
    if patch_httpx():
        patched.append("httpx")
    if patch_urllib():
        patched.append("urllib")
    
    if patched:
        print(f"✅ Patched libraries: {', '.join(patched)}")
    else:
        print("⚠️  No HTTP libraries found to patch (will use env vars)")
    
    print()
    print("⚠️  SSL verification: DISABLED (dev/test only!)")
    print("=" * 70)
    print()

# Auto-inject when module is imported
inject_mitm_proxy_advanced()

__all__ = ['inject_mitm_proxy_advanced', 'MITM_PROXY_URL', 'MITM_PROXY_PORT']
