#!/usr/bin/env python3
"""
install_mitm_cert.py

Robust mitmproxy CA installer.

What it does:
1. Try to download mitmproxy CA directly from http://mitm.it/cert/cer (NO PROXY).
2. If direct download fails, try to read the local mitmproxy CA file (~/.mitmproxy/mitmproxy-ca.pem or similar).
3. Install into the OS trust store:
   - Windows: certutil -> Root
   - Linux (Debian/Ubuntu): copy to /usr/local/share/ca-certificates/ and run update-ca-certificates
   - macOS: security add-trusted-cert into System keychain
4. Print next steps.

Run:
  sudo python install_mitm_cert.py --port 8082

Note: You must run mitmproxy (mitmdump/mitmweb) separately before using it for live interception.
"""

from __future__ import annotations
import os
import sys
import platform
import argparse
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Optional

# color fallback
try:
    from colorama import init as _color_init, Fore, Style
    _color_init()
except Exception:
    class Fore:
        GREEN = RED = YELLOW = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""

MITM_LOCAL_CERT_PATHS = [
    Path.home() / ".mitmproxy" / "mitmproxy-ca.pem",
    Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
    Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer",
]

def download_cert_direct(cert_url: str = "http://mitm.it/cert/cer", timeout: int = 20) -> Optional[Path]:
    """
    Attempt direct HTTP download WITHOUT using any proxy.
    This avoids the bootstrap trust paradox.
    """
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(cert_url, headers={"User-Agent": "mitm-cert-installer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            if not data:
                return None
            tmp = Path(tempfile.gettempdir()) / "mitmproxy-ca-cert.cer"
            tmp.write_bytes(data)
            return tmp
    except urllib.error.URLError as e:
        return None
    except Exception:
        return None

def find_local_mitm_cert() -> Optional[Path]:
    """Check common local mitmproxy cert locations."""
    for p in MITM_LOCAL_CERT_PATHS:
        if p.exists():
            return p
    return None

def install_windows(cert_path: Path) -> bool:
    """Use certutil to add to Root store (requires admin). Falls back to GUI if needed."""
    if not shutil.which("certutil"):
        print(f"{Fore.YELLOW}certutil not found on PATH.{Style.RESET_ALL}")
        return False
    
    # Try certutil first (silent install)
    cmd = ["certutil", "-addstore", "Root", str(cert_path)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"{Fore.GREEN}Certificate installed to Windows Root store.{Style.RESET_ALL}")
        return True
    
    # If certutil fails, open Windows certificate GUI for manual install
    print(f"{Fore.YELLOW}certutil failed (may need admin rights): {res.stderr.strip()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Opening Windows Certificate Manager GUI...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}In the wizard:{Style.RESET_ALL}")
    print(f"  1. Click 'Next'")
    print(f"  2. Select 'Place all certificates in the following store' → Browse")
    print(f"  3. Choose 'Trusted Root Certification Authorities'")
    print(f"  4. Click 'Next' → 'Finish' → Accept the security warning")
    
    try:
        # Open certificate with default Windows handler (Certificate Import Wizard)
        subprocess.run(["cmd", "/c", "start", "", str(cert_path)], check=True)
        print(f"\n{Fore.GREEN}Certificate UI opened. Complete the installation wizard above.{Style.RESET_ALL}")
        user_input = input(f"{Fore.YELLOW}Did you complete the installation? (y/n): {Style.RESET_ALL}").strip().lower()
        if user_input == 'y':
            print(f"{Fore.GREEN}Certificate installation confirmed by user.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}Certificate installation not completed.{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Failed to open certificate GUI: {e}{Style.RESET_ALL}")
        return False

def install_linux(cert_path: Path) -> bool:
    """
    Debian/Ubuntu approach: copy .crt to /usr/local/share/ca-certificates and run update-ca-certificates.
    Note: requires root.
    """
    dest = Path("/usr/local/share/ca-certificates") / "mitmproxy-ca.crt"
    try:
        shutil.copy2(str(cert_path), str(dest))
        res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"{Fore.GREEN}Certificate installed to system CA store.{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}update-ca-certificates failed: {res.stderr}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}Failed to install on Linux: {e}{Style.RESET_ALL}")
        return False

def install_macos(cert_path: Path) -> bool:
    """
    macOS: use security add-trusted-cert to System keychain. Requires sudo.
    """
    cmd = [
        "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", str(cert_path)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"{Fore.GREEN}Certificate added to system keychain.{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}security command failed: {res.stderr}{Style.RESET_ALL}")
        return False

def sanitize_cert_for_windows(cert_path: Path) -> Path:
    """certutil on Windows accepts DER or PEM; ensure file extension is .cer for UI friendliness."""
    if cert_path.suffix.lower() in (".pem", ".crt"):
        new = cert_path.with_suffix(".cer")
        shutil.copy2(cert_path, new)
        return new
    return cert_path

def main():
    ap = argparse.ArgumentParser(description="Install mitmproxy CA cert into system trust store (bootstrap-safe).")
    ap.add_argument("--port", "-p", default=8080, type=int, help="mitmproxy listening port (informational only).")
    ap.add_argument("--no-download", action="store_true", help="Don't attempt HTTP download; only try local cert file.")
    args = ap.parse_args()

    print(f"{Fore.CYAN}MITMPROXY CA INSTALLER (bootstrap-safe){Style.RESET_ALL}")
    # Step 1: try direct download without proxy
    cert_file = None
    if not args.no_download:
        print("Attempting direct HTTP download of mitmproxy CA (no proxy)...")
        cert_file = download_cert_direct()
        if cert_file:
            print(f"{Fore.GREEN}Downloaded CA to: {cert_file}{Style.RESET_ALL}")
    if not cert_file:
        print("Direct download failed or skipped. Checking local mitmproxy cert locations...")
        local = find_local_mitm_cert()
        if local:
            cert_file = local
            print(f"{Fore.GREEN}Found local mitmproxy file: {cert_file}{Style.RESET_ALL}")
    if not cert_file:
        print(f"{Fore.YELLOW}Could not find or download mitmproxy CA. Please run mitmproxy and visit http://mitm.it in your browser and install the certificate manually.{Style.RESET_ALL}")
        sys.exit(2)

    # Ensure we have admin privileges (best-effort check)
    system = platform.system()
    if system == "Linux" or system == "Darwin":
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}Warning: Root privileges are recommended to install system certificates. Re-run with sudo if installation fails.{Style.RESET_ALL}")
    elif system == "Windows":
        # can't easily check on all environments, but certutil will fail if needed
        pass

    # Install per OS
    success = False
    try:
        if system == "Windows":
            cert_to_use = sanitize_cert_for_windows(cert_file)
            success = install_windows(cert_to_use)
        elif system == "Linux":
            success = install_linux(cert_file)
        elif system == "Darwin":
            success = install_macos(cert_file)
        else:
            print(f"{Fore.RED}Unsupported OS: {system}{Style.RESET_ALL}")
            sys.exit(1)
    finally:
        # optional local cleanup for temporary download
        if cert_file and cert_file.exists() and cert_file.parent == Path(tempfile.gettempdir()):
            try:
                cert_file.unlink()
            except Exception:
                pass

    if success:
        print(f"\n{Fore.GREEN}Installation complete. Next steps:{Style.RESET_ALL}")
        print("  1) Restart your browser / app.")
        print(f"  2) Configure HTTP(S) proxy to point to 127.0.0.1:{args.port}")
        print("  3) For Python: export HTTP_PROXY and HTTPS_PROXY; set REQUESTS_CA_BUNDLE='' or use patched SSL context.")
    else:
        print(f"{Fore.RED}Installation failed. You can install the certificate manually by visiting http://mitm.it and following platform instructions.{Style.RESET_ALL}")
        sys.exit(3)

if __name__ == "__main__":
    main()
