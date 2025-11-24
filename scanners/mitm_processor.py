"""
MITM traffic processing utilities.

Handles parsing and processing of NDJSON traffic logs from inject_mitm_proxy.py.
"""
import json
from pathlib import Path


def parse_mitm_traffic(traffic_file):
    """
    Parse MITM traffic NDJSON file and extract findings.
    
    Args:
        traffic_file (Path): Path to mitm_traffic.ndjson file
        
    Returns:
        dict: Contains traffic_findings, proxied count, bypassed count, security_findings
    """
    proxied = 0
    bypassed = 0
    traffic_findings = []
    security_findings = []
    
    if not traffic_file.exists():
        return {
            "traffic_findings": [],
            "proxied": 0,
            "bypassed": 0,
            "security_findings": []
        }
    
    try:
        with traffic_file.open("r", encoding="utf-8") as tf:
            for line in tf:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    entry = json.loads(line)
                    stage = entry.get("stage")
                    
                    if stage == "mitm_outbound":
                        proxied += 1
                        traffic_findings.append({
                            "type": "mitm_proxied_request",
                            "severity": "INFO",
                            "timestamp": entry.get("ts"),
                            "timestamp_human": entry.get("timestamp"),
                            "client": entry.get("client"),
                            "method": entry.get("method"),
                            "url": entry.get("url"),
                            "description": f"Proxied request via MITM: {entry.get('method')} {entry.get('url')} (client={entry.get('client')})"
                        })
                    elif stage == "mitm_bypass":
                        bypassed += 1
                    elif stage == "security_finding":
                        security_findings.append({
                            "type": entry.get("type"),
                            "severity": entry.get("severity"),
                            "timestamp": entry.get("ts"),
                            "timestamp_human": entry.get("timestamp"),
                            "description": entry.get("description"),
                            "url": entry.get("url"),
                            "client": entry.get("client"),
                            "method": entry.get("method"),
                            "pattern": entry.get("pattern"),
                            "field": entry.get("field"),
                            "header": entry.get("header"),
                        })
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    
    return {
        "traffic_findings": traffic_findings,
        "proxied": proxied,
        "bypassed": bypassed,
        "security_findings": security_findings
    }
