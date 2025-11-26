"""
Browser-based runtime scanner using Playwright.

This module uses Playwright to load applications in a real browser and inspect
runtime state including localStorage, sessionStorage, cookies, and global variables.
"""

# Optional Playwright import
USE_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    USE_PLAYWRIGHT = True
except ImportError:
    USE_PLAYWRIGHT = False


def playwright_inspect(target):
    """
    Use Playwright to load the application in a real browser and inspect runtime state.
    
    This provides visibility into client-side storage and global variables that may
    contain secrets not visible in static analysis:
    - localStorage: Persistent browser storage
    - sessionStorage: Session-scoped browser storage
    - cookies: HTTP cookies set by the application
    - Global variables: window.__ENV or similar configuration objects
    
    Args:
        target (str): URL to navigate to (e.g., "http://localhost:8000")
        
    Returns:
        dict: Contains localStorage, sessionStorage, cookies, globals objects, or error info
        
    Prerequisites:
        - playwright library installed (pip install playwright)
        - Playwright browsers installed (python -m playwright install)
        
    Use Cases:
        - Detect secrets stored in browser storage (common developer mistake)
        - Find API keys exposed via window.config or window.__ENV
        - Identify insecure cookie configurations
        
    Limitations:
        - Requires graphical environment or headless mode
        - Slower than static analysis (launches real browser)
        - May not catch secrets loaded after initial page load
        - 20 second timeout may be too short for slow apps
    """
    if not USE_PLAYWRIGHT:
        return {
            "error": "playwright-not-installed",
            "message": "Install with: pip install playwright && python -m playwright install"
        }
    
    out = {"localStorage": {}, "sessionStorage": {}, "cookies": [], "globals": {}}
    
    try:
        with sync_playwright() as p:
            # Launch Chromium browser in headless mode
            browser = p.chromium.launch()
            page = browser.new_page()
            
            # Navigate to target and wait for network to be idle
            page.goto(target, wait_until="networkidle", timeout=20000)
            
            # Extract localStorage contents
            out["localStorage"] = page.evaluate("""() => {
                const r = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    r[k] = localStorage.getItem(k);
                }
                return r;
            }""")
            
            # Extract sessionStorage contents
            out["sessionStorage"] = page.evaluate("""() => {
                const r = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    r[k] = sessionStorage.getItem(k);
                }
                return r;
            }""")
            
            # Get all cookies
            out["cookies"] = page.context.cookies()
            
            # Check for common global configuration objects
            try:
                out["globals"]["__ENV"] = page.evaluate("() => window.__ENV || null")
                out["globals"]["config"] = page.evaluate("() => window.config || null")
                out["globals"]["API_KEY"] = page.evaluate("() => window.API_KEY || null")
            except Exception:
                pass  # Global may not exist
            
            browser.close()
            
    except Exception as e:
        return {
            "error": "playwright-failed",
            "exception": str(e),
            "message": "Failed to launch browser or navigate to target"
        }
    
    return out


def process_browser_findings(browser_data):
    """
    Process browser runtime data and extract security findings.
    
    Args:
        browser_data (dict): Output from playwright_inspect()
        
    Returns:
        list: Security findings from browser storage, cookies, and globals
    """
    findings = []
    
    if "error" in browser_data:
        return findings
    
    # localStorage
    for k, v in browser_data.get("localStorage", {}).items():
        if any(t in k.lower() for t in ["token", "key", "secret", "api"]):
            findings.append({
                "type": "browser_storage",
                "location": "localStorage",
                "key": k,
                "value": "[REDACTED]",
                "original_length": len(str(v))
            })
    
    # sessionStorage
    for k, v in browser_data.get("sessionStorage", {}).items():
        if any(t in k.lower() for t in ["token", "key", "secret", "api"]):
            findings.append({
                "type": "browser_storage",
                "location": "sessionStorage",
                "key": k,
                "value": "[REDACTED]",
                "original_length": len(str(v))
            })
    
    # insecure cookies
    for c in browser_data.get("cookies", []):
        if not c.get("secure") or not c.get("httpOnly"):
            findings.append({
                "type": "cookie_insecure",
                "name": c["name"],
                "secure": c.get("secure"),
                "httpOnly": c.get("httpOnly")
            })
    
    # exposed globals
    for k, v in browser_data.get("globals", {}).items():
        if v not in (None, "", False):
            findings.append({
                "type": "browser_global",
                "key": k,
                "value": "[REDACTED]",
                "original_length": len(str(v))
            })
    
    return findings
