#!/usr/bin/env python3
"""
Example: How to integrate MITM proxy into your FastAPI backend

This shows the REQUIRED first-line import for MITM traffic capture.
"""

# ============================================
# CRITICAL: This MUST be the FIRST import!
# ============================================
from cybersec_scanner.scanners.inject_mitm_proxy import inject_mitm_proxy_advanced
inject_mitm_proxy_advanced()

# ============================================
# Now you can import your app framework
# ============================================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="Example Backend with MITM")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello World"}

@app.get("/api/test")
def test_endpoint():
    """Test endpoint that makes an outbound HTTP request"""
    import requests
    # This request will be captured by MITM proxy
    response = requests.get("https://httpbin.org/json")
    return {"status": "success", "data": response.json()}

if __name__ == "__main__":
    # When you run this file, you should see:
    # [MITM] Proxy active on http://127.0.0.1:8082
    # [MITM] Bypass mode: AWS, OAuth, AI providers, payments, CDNs
    # [MITM] Patched libraries: requests, httpx, urllib, urllib3, aiohttp
    
    print("\n" + "="*60)
    print("Backend starting with MITM proxy enabled")
    print("Traffic will be logged to: mitm_traffic.ndjson")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
