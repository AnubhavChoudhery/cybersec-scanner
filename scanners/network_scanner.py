"""
Network packet capture scanner using Scapy.

This module captures network packets to detect plaintext HTTP traffic
containing secrets. Note: HTTPS traffic cannot be decrypted.
"""
import sys
import os

# Optional scapy import
USE_SCAPY = False
try:
    from scapy.all import sniff, TCP, Raw
    USE_SCAPY = True
except ImportError:
    USE_SCAPY = False

# Global list to collect captured packets
pcap_capture_results = []


def scapy_packet_callback(pkt):
    """
    Callback function for scapy packet capture.
    
    Analyzes TCP packets with raw data payload to detect HTTP requests/responses.
    Only captures plaintext HTTP (HTTPS payloads are encrypted and not visible).
    
    Args:
        pkt: Scapy packet object
        
    Side Effects:
        Appends findings to global pcap_capture_results list
    """
    try:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            raw = pkt[Raw].load
            try:
                text = raw.decode('utf-8', errors='ignore')
            except Exception:
                text = None
            if text:
                # crude HTTP request detection
                if text.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
                    # capture first 2000 chars
                    pcap_capture_results.append({"type": "http_request", "payload": text[:2000]})
                elif "HTTP/" in text:
                    pcap_capture_results.append({"type": "http_response", "payload": text[:2000]})
    except Exception:
        pass


def check_pcap_privileges():
    """
    Check if the current process has sufficient privileges for packet capture.
    
    Returns:
        tuple: (has_privileges: bool, error_message: str or None)
        
    Platform-specific behavior:
        - Linux/Unix: Checks if running as root (UID 0)
        - Windows: Checks if running with administrator privileges
        - MacOS: Same as Linux (requires root)
        
    Notes:
        On Windows, even with admin privileges, Npcap or WinPcap must be installed
        for scapy to function properly.
    """
    if sys.platform == "win32":
        # Windows: Check for administrator privileges
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                return False, "Administrator privileges required for packet capture on Windows. Run as Administrator."
            # Even with admin, check if we can actually capture
            # Note: This doesn't check for Npcap/WinPcap installation
            return True, None
        except Exception as e:
            return False, f"Unable to check Windows privileges: {e}"
    else:
        # Unix-like systems (Linux, MacOS): Check if running as root
        try:
            if os.geteuid() != 0:
                return False, "Root privileges required for packet capture. Run with sudo."
            return True, None
        except AttributeError:
            # os.geteuid() not available (shouldn't happen on Unix, but just in case)
            return False, "Unable to check privileges on this platform"


def run_packet_capture(timeout=15, filter_expr=None):
    """
    Capture network packets for a specified duration to detect plaintext HTTP traffic.
    
    Args:
        timeout (int): Duration in seconds to capture packets (default: 15)
        filter_expr (str): Optional BPF filter expression (e.g., "tcp port 80")
        
    Returns:
        dict: Result dictionary with either:
            - {"captured": int} on success
            - {"error": str, ...} on failure
            
    Prerequisites:
        - scapy library installed (pip install scapy)
        - Root/administrator privileges
        - On Windows: Npcap or WinPcap installed
        
    Limitations:
        - Cannot decrypt HTTPS/TLS traffic (encrypted)
        - Only useful for detecting plaintext HTTP communication
        - May trigger antivirus/security software warnings
        - Performance impact on system during capture
        
    Security Notes:
        This feature is primarily useful for detecting if your localhost app
        accidentally sends sensitive data over plaintext HTTP instead of HTTPS.
    """
    if not USE_SCAPY:
        return {
            "error": "scapy-not-installed",
            "message": "Install scapy with: pip install scapy"
        }
    
    # Check for required privileges (platform-specific)
    has_privileges, error_msg = check_pcap_privileges()
    if not has_privileges:
        return {
            "error": "insufficient-privileges",
            "message": error_msg
        }
    
    print(f"[*] Starting packet capture for {timeout}s...")
    if sys.platform == "win32":
        print("    Note: Ensure Npcap or WinPcap is installed on Windows")
    
    try:
        if filter_expr:
            sniff(filter=filter_expr, prn=scapy_packet_callback, timeout=timeout)
        else:
            # Default filter: capture HTTP traffic (port 80)
            sniff(filter="tcp port 80", prn=scapy_packet_callback, timeout=timeout)
    except PermissionError as e:
        return {
            "error": "permission-denied",
            "message": f"Permission denied during packet capture: {e}",
            "hint": "On Windows, ensure you're running as Administrator and Npcap is installed"
        }
    except Exception as e:
        return {
            "error": "pcap-failed",
            "exception": str(e),
            "message": "Packet capture failed. Check privileges and network adapter status."
        }
    
    return {"captured": len(pcap_capture_results)}
