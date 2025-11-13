#!/usr/bin/env python3
"""
network_scanner.py

Launch and control a mitmdump (mitmproxy headless) process with a generated addon that:
 - Ignores OAuth / identity / AI-provider hosts by default
 - Captures request/response metadata and limited bodies
 - Writes JSON results to a temporary file

Functions:
 - run_mitm_dump(port=8082, duration=None) -> (process, results_path)
 - stop_mitm_dump(process, results_path) -> dict results

Requires: mitmproxy (mitmdump) installed in PATH or venv.
Install: pip install mitmproxy
"""

from __future__ import annotations
import os
import sys
import tempfile
import time
import json
import atexit
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional

# Try importing colorama for pretty output (optional)
try:
    from colorama import init as _cinit, Fore, Style
    _cinit()
except Exception:
    class Fore:
        CYAN = GREEN = YELLOW = RED = WHITE = ""
    class Style:
        RESET_ALL = ""

RESULTS_TEMPLATE = {
    "requests": 0,
    "responses": 0,
    "ignored": 0,
    "findings": [],
    "captured": 0,
    "traffic_sample": [],
    "severity_summary": {}
}

# Default ignore regex for heavy/identity providers (adjustable)
DEFAULT_IGNORE_HOSTS_REGEX = r"(" + "|".join([
    r"accounts\.google\.com",
    r"oauth2\.googleapis\.com",
    r".*\.googleapis\.com",
    r"login\.microsoftonline\.com",
    r"login\.live\.com",
    r"auth0\.com",
    r"okta\.com"]) + r")"

def _find_mitmdump_exe() -> Optional[str]:
    candidates = [
        shutil.which("mitmdump"),
        shutil.which("mitmproxy"),
        shutil.which("mitmproxy.exe"),
        shutil.which("mitmdump.exe")
    ]
    for c in candidates:
        if c:
            return c
    return None

def _render_addon_file(results_file: str, ignore_hosts_regex: str) -> str:
    """Create a small mitmproxy addon that writes JSON results to results_file."""
    addon_py = f"""
import json, re
from mitmproxy import http
from datetime import datetime

RESULTS = {{
    'requests': 0,
    'responses': 0,
    'ignored': 0,
    'findings': [],
    'captured': 0,
    'traffic_sample': []
}}

IGNORE_RE = re.compile(r\"\"\"{ignore_hosts_regex}\"\"\", re.I)

def should_ignore(flow):
    host = getattr(flow.request, 'host', '') or ''
    if IGNORE_RE.search(host):
        return True
    url = getattr(flow.request, 'pretty_url', '') or ''
    low = url.lower()
    for token in ('oauth', 'sso', 'openid', '/auth/', '/login'):
        if token in low:
            return True
    return False

def request(flow: http.HTTPFlow):
    if should_ignore(flow):
        RESULTS['ignored'] += 1
        return
    RESULTS['requests'] += 1
    entry = {{
        'type': 'request',
        'method': flow.request.method,
        'url': flow.request.pretty_url,
        'headers': dict(flow.request.headers),
        'timestamp': datetime.utcnow().isoformat()
    }}
    if flow.request.content:
        try:
            entry['body'] = flow.request.content.decode('utf-8', errors='ignore')[:10000]
        except:
            entry['body'] = '<binary>'
    RESULTS['traffic_sample'].append(entry)
    if len(RESULTS['traffic_sample']) > 200:
        RESULTS['traffic_sample'].pop(0)

def response(flow: http.HTTPFlow):
    if should_ignore(flow):
        return
    RESULTS['responses'] += 1
    entry = {{
        'type': 'response',
        'url': flow.request.pretty_url,
        'status_code': getattr(flow.response, 'status_code', None),
        'headers': dict(flow.response.headers),
        'timestamp': datetime.utcnow().isoformat()
    }}
    if flow.response.content:
        try:
            entry['body'] = flow.response.content.decode('utf-8', errors='ignore')[:10000]
        except:
            entry['body'] = '<binary>'
    RESULTS['traffic_sample'].append(entry)
    if len(RESULTS['traffic_sample']) > 200:
        RESULTS['traffic_sample'].pop(0)

def done():
    # Basic lightweight analysis stub (extendable)
    RESULTS['captured'] = len(RESULTS['traffic_sample'])
    with open(r'''{results_file}''', 'w', encoding='utf-8') as f:
        json.dump(RESULTS, f, indent=2)
"""
    f = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py", encoding="utf-8")
    f.write(addon_py)
    f.flush()
    f.close()
    return f.name

def run_mitm_dump(port: int = 8082, duration: Optional[int] = None, ignore_hosts_regex: str = DEFAULT_IGNORE_HOSTS_REGEX) -> Tuple[Optional[subprocess.Popen], str]:
    """
    Start mitmdump in background with our addon. Returns (process, results_file_path).
    If mitmdump not found, returns (None, {"error":...})
    """
    mitmdump = _find_mitmdump_exe()
    if not mitmdump:
        raise FileNotFoundError("mitmdump not found. Install mitmproxy (pip install mitmproxy)")

    results_file = os.path.join(tempfile.gettempdir(), f"mitm_results_{port}.json")
    addon_file = _render_addon_file(results_file, ignore_hosts_regex)

    cmd = [
        mitmdump,
        "-p", str(port),
        "-s", addon_file,
        "--set", "stream_large_bodies=10m",
        "--set", "anticache=true",
        "--set", "anticomp=false",
        "--set", "body_size_limit=100m",
        "--set", "connection_strategy=lazy",
        "--set", "flow_detail=2"
    ]

    # start process
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, preexec_fn=(os.setsid if hasattr(os, "setsid") else None))
    atexit.register(lambda: proc.terminate() if proc and proc.poll() is None else None)

    # wait a moment for startup
    time.sleep(2.0)
    if proc.poll() is not None:
        # died early; collect output
        out, _ = proc.communicate(timeout=1)
        raise RuntimeError(f"mitmdump exited: {out}")

    # if duration set, we spawn a background timer to stop after duration
    if duration and duration > 0:
        def _timer_stop():
            time.sleep(duration)
            try:
                proc.terminate()
            except Exception:
                pass
        import threading
        threading.Thread(target=_timer_stop, daemon=True).start()

    return proc, results_file

def stop_mitm_dump(proc: subprocess.Popen, results_file: str, wait: float = 1.0) -> dict:
    """Stop mitmdump process and return parsed results (if any)."""
    if not proc:
        return {"error": "no-process"}
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    except Exception:
        pass

    # allow addon to write results
    time.sleep(wait)
    if os.path.exists(results_file):
        try:
            with open(results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # cleanup
            try:
                os.remove(results_file)
            except Exception:
                pass
            return data
        except Exception as e:
            return {"error": "read_failed", "message": str(e)}
    else:
        return {"error": "no_results", "message": "No results file produced"}

if __name__ == "__main__":
    # Quick CLI: start for 30s and print minimal summary
    print(f"{Fore.CYAN}Starting mitmdump for a quick capture (30s). Ctrl-C to stop early.{Style.RESET_ALL}")
    p, rs = run_mitm_dump(port=8082, duration=30)
    print("mitmdump running (pid):", p.pid if p else None)
    # wait until process exits if duration was set
    if p:
        try:
            p.wait()
        except KeyboardInterrupt:
            print("Keyboard interrupt, stopping.")
            pass
    print("Stopping and reading results...")
    res = stop_mitm_dump(p, rs)
    print("Results:", json.dumps(res if isinstance(res, dict) else {}, indent=2)[:1000])
