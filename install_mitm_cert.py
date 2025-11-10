"""
Automated mitmproxy certificate installation script.

USAGE:
    Windows (PowerShell as Administrator):
        python install_mitm_cert.py
    
    Linux/Mac:
        sudo python install_mitm_cert.py

PREREQUISITES:
    - mitmproxy must be running on the specified port (default: 8080)
    - Run with Administrator/sudo privileges

The script will:
1. Download the mitmproxy CA certificate from http://mitm.it
2. Install it to the system's trusted certificate store
3. Verify installation
"""

import os
import sys
import subprocess
import urllib.request
import tempfile
import platform
import shutil

try:
    from colorama import init, Fore, Style
    init()
    USE_COLORAMA = True
except ImportError:
    # Fallback to no colors
    class Fore:
        GREEN = YELLOW = RED = CYAN = LIGHTBLUE_EX = ""
    class Style:
        RESET_ALL = ""
    USE_COLORAMA = False


def check_privileges():
    """Check if running with required privileges"""
    system = platform.system()
    
    if system == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print(f"{Fore.RED}✗ Administrator privileges required{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}To run as Administrator:{Style.RESET_ALL}")
                print(f"  1. Right-click Command Prompt")
                print(f"  2. Select 'Run as Administrator'")
                print(f"  3. Run: python {os.path.basename(__file__)}")
                return False
        except:
            print(f"{Fore.YELLOW}⚠ Unable to verify admin privileges{Style.RESET_ALL}")
            return True
    else:
        if os.geteuid() != 0:
            print(f"{Fore.RED}✗ Root privileges required{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Run with sudo:{Style.RESET_ALL}")
            print(f"  sudo python {os.path.basename(__file__)}")
            return False
    
    return True


def download_cert(proxy_port=8080):
    """Download mitmproxy certificate"""
    print(f"\n{Fore.CYAN}[1/3] Downloading certificate...{Style.RESET_ALL}")
    
    # Set proxy for this request only
    proxy = urllib.request.ProxyHandler({
        'http': f'http://127.0.0.1:{proxy_port}',
        'https': f'http://127.0.0.1:{proxy_port}'
    })
    opener = urllib.request.build_opener(proxy)
    
    cert_url = "http://mitm.it/cert/cer"
    cert_path = os.path.join(tempfile.gettempdir(), "mitmproxy-ca-cert.cer")
    
    try:
        print(f"  Connecting to mitmproxy on port {proxy_port}...")
        with opener.open(cert_url, timeout=10) as response:
            with open(cert_path, 'wb') as f:
                f.write(response.read())
        
        file_size = os.path.getsize(cert_path)
        print(f"{Fore.GREEN}  ✓ Certificate downloaded ({file_size} bytes){Style.RESET_ALL}")
        print(f"  Location: {cert_path}")
        return cert_path
    
    except urllib.error.URLError as e:
        print(f"{Fore.RED}  ✗ Failed to download certificate{Style.RESET_ALL}")
        print(f"  Error: {e}")
        print(f"\n{Fore.YELLOW}Make sure mitmproxy is running:{Style.RESET_ALL}")
        print(f"  mitmdump -p {proxy_port}")
        return None
    except Exception as e:
        print(f"{Fore.RED}  ✗ Unexpected error: {e}{Style.RESET_ALL}")
        return None


def install_cert_windows(cert_path):
    """Install certificate on Windows"""
    print(f"\n{Fore.CYAN}[2/3] Installing certificate (Windows)...{Style.RESET_ALL}")
    
    try:
        # Check if certutil is available
        if not shutil.which('certutil'):
            print(f"{Fore.RED}  ✗ certutil not found{Style.RESET_ALL}")
            return False
        
        print(f"  Installing to Trusted Root Certification Authorities...")
        result = subprocess.run(
            ['certutil', '-addstore', 'Root', cert_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}  ✓ Certificate installed successfully!{Style.RESET_ALL}")
            
            # Verify installation
            print(f"\n{Fore.CYAN}[3/3] Verifying installation...{Style.RESET_ALL}")
            verify_result = subprocess.run(
                ['certutil', '-store', 'Root', 'mitmproxy'],
                capture_output=True,
                text=True
            )
            
            if 'mitmproxy' in verify_result.stdout.lower():
                print(f"{Fore.GREEN}  ✓ Certificate verified in Root store{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}  ⚠ Certificate installed but not found in verification{Style.RESET_ALL}")
            
            return True
        else:
            print(f"{Fore.RED}  ✗ Installation failed{Style.RESET_ALL}")
            print(f"  Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}  ✗ Error installing certificate: {e}{Style.RESET_ALL}")
        return False


def install_cert_linux(cert_path):
    """Install certificate on Linux"""
    print(f"\n{Fore.CYAN}[2/3] Installing certificate (Linux)...{Style.RESET_ALL}")
    
    try:
        # Copy to ca-certificates directory
        dest = "/usr/local/share/ca-certificates/mitmproxy.crt"
        print(f"  Copying to {dest}...")
        
        subprocess.run(['cp', cert_path, dest], check=True)
        
        print(f"  Updating certificate store...")
        result = subprocess.run(
            ['update-ca-certificates'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}  ✓ Certificate installed successfully!{Style.RESET_ALL}")
            
            # Verify
            print(f"\n{Fore.CYAN}[3/3] Verifying installation...{Style.RESET_ALL}")
            if os.path.exists(dest):
                print(f"{Fore.GREEN}  ✓ Certificate exists at {dest}{Style.RESET_ALL}")
            
            return True
        else:
            print(f"{Fore.RED}  ✗ Installation failed{Style.RESET_ALL}")
            print(f"  Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}  ✗ Error installing certificate: {e}{Style.RESET_ALL}")
        return False


def install_cert_macos(cert_path):
    """Install certificate on macOS"""
    print(f"\n{Fore.CYAN}[2/3] Installing certificate (macOS)...{Style.RESET_ALL}")
    
    try:
        print(f"  Adding to system keychain...")
        result = subprocess.run([
            'security', 'add-trusted-cert',
            '-d', '-r', 'trustRoot',
            '-k', '/Library/Keychains/System.keychain',
            cert_path
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}  ✓ Certificate installed successfully!{Style.RESET_ALL}")
            
            # Verify
            print(f"\n{Fore.CYAN}[3/3] Verifying installation...{Style.RESET_ALL}")
            verify_result = subprocess.run([
                'security', 'find-certificate', '-c', 'mitmproxy',
                '/Library/Keychains/System.keychain'
            ], capture_output=True, text=True)
            
            if verify_result.returncode == 0:
                print(f"{Fore.GREEN}  ✓ Certificate verified in system keychain{Style.RESET_ALL}")
            
            return True
        else:
            print(f"{Fore.RED}  ✗ Installation failed{Style.RESET_ALL}")
            print(f"  Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}  ✗ Error installing certificate: {e}{Style.RESET_ALL}")
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Install mitmproxy CA certificate to system trust store",
        epilog="Requires Administrator/sudo privileges and running mitmproxy instance"
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8080,
        help='Port where mitmproxy is running (default: 8080)'
    )
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}MITMPROXY CERTIFICATE INSTALLER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # Check privileges
    if not check_privileges():
        sys.exit(1)
    
    print(f"{Fore.GREEN}✓ Running with required privileges{Style.RESET_ALL}")
    
    # Download certificate
    cert_path = download_cert(proxy_port=args.port)
    if not cert_path:
        sys.exit(1)
    
    # Install based on OS
    system = platform.system()
    success = False
    
    if system == "Windows":
        success = install_cert_windows(cert_path)
    elif system == "Linux":
        success = install_cert_linux(cert_path)
    elif system == "Darwin":  # macOS
        success = install_cert_macos(cert_path)
    else:
        print(f"{Fore.RED}✗ Unsupported OS: {system}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Cleanup
    try:
        os.remove(cert_path)
    except:
        pass
    
    # Final message
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    if success:
        print(f"{Fore.GREEN}✓ INSTALLATION COMPLETE!{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}NEXT STEPS:{Style.RESET_ALL}")
        print(f"  1. Restart your browser/application")
        print(f"  2. Configure proxy settings:")
        print(f"     HTTP Proxy:  127.0.0.1:{args.port}")
        print(f"     HTTPS Proxy: 127.0.0.1:{args.port}")
        print(f"  3. Your HTTPS traffic will now be inspectable")
    else:
        print(f"{Fore.RED}✗ INSTALLATION FAILED{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Manual installation:{Style.RESET_ALL}")
        print(f"  1. Set proxy to 127.0.0.1:{args.port}")
        print(f"  2. Visit http://mitm.it in browser")
        print(f"  3. Download and install certificate for your OS")
        sys.exit(1)
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
