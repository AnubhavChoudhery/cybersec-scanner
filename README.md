# Web Application Security Audit Tool

A comprehensive security scanner for web applications that detects hardcoded secrets, exposed endpoints, configuration vulnerabilities, and runtime security issues. Supports static analysis, git history scanning, web crawling, browser runtime inspection, and HTTPS traffic interception.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [MITM Proxy Setup](#mitm-proxy-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Scanner Modules](#scanner-modules)
- [Output Format](#output-format)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Features

### Core Capabilities
- **Git History Scanning**: Detect secrets in commit history using efficient pickaxe search
- **Web Crawling**: Discover exposed endpoints, analyze JavaScript files and source maps
- **Browser Runtime Inspection**: Check localStorage, sessionStorage, cookies, and global variables
- **HTTPS Traffic Interception**: Real-time inspection of encrypted HTTPS requests and responses
- **Pattern Matching**: 58+ built-in patterns for AWS, OpenAI, Stripe, GitHub, databases, and more

### Detection Coverage

- API keys and access tokens (AWS, Google Cloud, Azure, OpenAI, Anthropic, Groq, etc.)
- Database connection strings (MongoDB, PostgreSQL, MySQL, Redis)
- Payment credentials (Stripe, PayPal, Square)
- Authentication tokens (JWT, OAuth, Basic Auth)
- Private keys (RSA, SSH, PGP)
- Plaintext passwords and weak credentials
- Secrets in URL query parameters
- Leaked secrets in HTTP responses

## Architecture

```
Chrome_Ext/
├── local_check.py              # Main orchestrator
├── config.py                   # Configuration and patterns
├── utils.py                    # Utility functions
├── patterns.env                # Secret detection patterns (user-configured)
├── inject_mitm_proxy.py        # MITM proxy injection module
├── install_mitm_cert.py        # Certificate installation helper
├── scanners/
│   ├── git_scanner.py         # Git history analysis
│   ├── web_crawler.py         # HTTP endpoint scanning
│   ├── browser_scanner.py     # Playwright runtime inspection
│   └── network_scanner.py     # MITM proxy traffic analysis
└── audit_report.json          # Output report (generated)
```

## Installation

### System Requirements

- Python 3.8 or higher
- Git (for git history scanning)
- mitmproxy 10.0+ (for HTTPS inspection)
- Modern web browser (for Playwright scanner)

### Required Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install manually:

```bash
pip install requests colorama
```

### Optional Dependencies

#### For HTTPS Traffic Inspection
```bash
# Install mitmproxy
pip install mitmproxy

# Verify installation
mitmdump --version
```

#### For Browser Runtime Inspection
```bash
pip install playwright
python -m playwright install
```

#### For Network Packet Capture (Advanced)
```bash
pip install scapy

# Windows: Install Npcap from https://npcap.com/
# Linux/Mac: May require libpcap
```

## Quick Start

### Initial Setup

1. **Clone or download the repository**

2. **Set up pattern file** (REQUIRED before first run)

```bash
# Copy the patterns file template
cp patterns.env.example patterns.env

# The file includes 58+ detection patterns for major providers
# Edit patterns.env to customize or add patterns (optional)
```

3. **Verify setup**

```bash
python -c "from config import KNOWN_PATTERNS; print(f'Loaded {len(KNOWN_PATTERNS)} patterns')"
```

Expected output: `Loaded 58 patterns` (or similar)

### Basic Usage

```bash
# Scan with default settings
python local_check.py --target http://localhost:8000 --root /path/to/project

# Generate audit report
cat audit_report.json
```

## MITM Proxy Setup

The MITM (Man-in-the-Middle) proxy feature allows inspection of HTTPS traffic in real-time, including request/response headers and bodies.

### Prerequisites

1. **Install mitmproxy**

```bash
pip install mitmproxy

# Verify installation
mitmdump --version
```

2. **Copy required files to your backend**

```bash
# From the Chrome_Ext directory
cp inject_mitm_proxy.py /path/to/your/backend/app/
cp patterns.env /path/to/your/backend/app/
```

### Backend Integration

Add the following import as the **FIRST LINE** of your main application file:

**For FastAPI:**
```python
# backend/app/main.py
import inject_mitm_proxy  # MUST BE FIRST IMPORT

from fastapi import FastAPI
# ... rest of your imports and code
```

**For Flask:**
```python
# backend/app.py
import inject_mitm_proxy  # MUST BE FIRST IMPORT

from flask import Flask
# ... rest of your imports and code
```

**For Django:**
```python
# backend/manage.py or wsgi.py
import inject_mitm_proxy  # MUST BE FIRST IMPORT

# ... rest of Django setup
```

### Running with MITM Proxy

1. **Start your backend application**

```bash
# No environment variables needed - proxy is always enabled
# Just start your backend normally
uvicorn app.main:app --reload  # FastAPI example
```

You should see:
```
[MITM] Proxy active on http://127.0.0.1:8082
[MITM] Bypass mode: AWS, OAuth, AI providers, payments, CDNs
[MITM] Patched libraries: requests, httpx, urllib, urllib3, aiohttp
```

2. **Run the security scanner**

```bash
# In a new terminal, run the scanner with MITM enabled
python local_check.py \
  --target http://localhost:8000 \
  --enable-mitm \
  --mitm-port 8082
```

3. **Interact with your application** (make HTTP requests, use API endpoints, etc.)

4. **Stop the scanner** (Ctrl+C) to generate the audit report

5. **Review results**

```bash
# View audit report
cat audit_report.json

# View traffic log (raw NDJSON)
cat mitm_traffic.ndjson
```

### MITM Proxy Detection Capabilities

The MITM proxy inspects both requests and responses for security issues:

**Request-Side Detection:**
- Credentials embedded in URLs (`user:pass@domain`)
- API keys in query parameters (`?api_key=xxx`)
- Basic Authentication headers (base64 credentials)
- API keys in Authorization headers (with context awareness)
- Plaintext passwords in request bodies (excludes bcrypt/argon2 hashes)
- Secrets matching any of the 58+ patterns

**Response-Side Detection:**
- Secrets leaked in response headers
- API keys in response bodies (JSON, HTML, JavaScript)
- Credentials in error messages
- Database connection strings in stack traces
- Debug information containing sensitive data

**Severity Levels:**
- `CRITICAL`: API keys in URLs, credentials over HTTP, plaintext passwords
- `HIGH`: API keys in headers over HTTPS (with expected auth disclaimer)
- `INFO`: Normal traffic logging (not a security issue)

### MITM Proxy Configuration

The `inject_mitm_proxy.py` module works automatically when imported. The only optional configuration is:

```bash
# Set custom MITM proxy port (default: 8082)
export MITM_PROXY_PORT=9000
```

**No other environment variables needed** - the proxy runs in full mode by default with intelligent domain bypass.

### Domain Bypass Configuration

By default, the following domains bypass the MITM proxy to prevent authentication and SSL issues:

**OAuth Providers:**
- `accounts.google.com`, `oauth2.googleapis.com`, `login.microsoftonline.com`

**AI Providers:**
- `api.openai.com`, `openai.com`
- `api.anthropic.com`, `anthropic.com`
- `api.groq.com`, `groq.com`
- `api.mistral.ai`, `mistral.ai`
- `api-inference.huggingface.co`, `huggingface.co`
- `api.cohere.ai`, `replicate.com`, `together.xyz`, `anyscale.com`, `perplexity.ai`

**AWS Services:**
- All `*.amazonaws.com` domains
- API Gateway, Lambda, S3, CloudFront

**Payment Providers:**
- `stripe.com`, `paypal.com`

**CDNs:**
- `cloudflare.com`, `cloudfront.net`

**Localhost:**
- `127.0.0.1`, `localhost`

To modify bypass rules, edit the `BYPASS_DOMAINS` and `AWS_SUFFIXES` sets in `inject_mitm_proxy.py`.

### Uninstalling MITM Proxy

To remove MITM proxy from your backend:

1. Remove or comment out the import:
```python
# import inject_mitm_proxy  # Disabled
```

2. Restart your backend application

The proxy is only active when the module is imported.

## Configuration

### Pattern File (patterns.env)

The `patterns.env` file contains regular expressions for detecting secrets. This file is excluded from version control to prevent triggering GitHub security alerts.

**Format:**
```
PATTERN_NAME=regex_pattern
```

**Adding custom patterns:**
```bash
# Edit patterns.env
nano patterns.env

# Add your pattern
MY_CUSTOM_KEY=mykey_[0-9a-f]{32}

# Reload the scanner
python local_check.py --target http://localhost:8000
```

### Configuration File (config.py)

**Entropy Threshold:**
```python
ENTROPY_THRESHOLD = 3.5  # Shannon entropy for randomness detection
```

**File Exclusions:**
```python
EXCLUDE_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
    '.zip', '.tar', '.gz', '.pdf', '.exe', '.dll'
}
```

**Probe Paths (for web crawler):**
```python
PROBE_PATHS = [
    '/.env', '/.env.local', '/.env.production',
    '/.git/config', '/.git/HEAD',
    '/config.php.bak', '/backup.sql'
]
```

## Usage

### Command-Line Options

```bash
python local_check.py [OPTIONS]
```

**Core Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--target`, `-t` | URL | `http://localhost:8000` | Target application URL |
| `--root`, `-r` | Path | `.` | Repository root for static analysis |
| `--out`, `-o` | Path | `audit_report.json` | Output report filename |

**Scanner Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--depth` | Integer | `300` | Maximum pages to crawl |
| `--enable-playwright` | Flag | `False` | Enable browser runtime inspection |
| `--enable-pcap` | Flag | `False` | Enable packet capture (requires root) |
| `--pcap-timeout` | Integer | `12` | Packet capture duration (seconds) |

**MITM Proxy Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--enable-mitm` | Flag | `False` | Enable MITM proxy for HTTPS inspection |
| `--mitm-port` | Integer | `8082` | MITM proxy port |
| `--mitm-duration` | Integer | `0` | Auto-stop after N seconds (0 = manual) |
| `--mitm-traffic` | Path | Auto-detect | Custom path to traffic NDJSON file |

### Usage Examples

**Basic scan:**
```bash
python local_check.py --target http://localhost:8000 --root /path/to/project
```

**Full scan with all features:**
```bash
python local_check.py \
  --target http://localhost:3000 \
  --root ~/myapp \
  --enable-playwright \
  --enable-mitm \
  --depth 500 \
  --out security_report.json
```

**MITM-only scan (skip static/git):**
```bash
python local_check.py \
  --target http://localhost:8000 \
  --enable-mitm \
  --mitm-duration 30
```

**Custom traffic log location:**
```bash
python local_check.py \
  --target http://localhost:8000 \
  --enable-mitm \
  --mitm-traffic /custom/path/to/traffic.ndjson
```

## Scanner Modules

### 1. Git Scanner (`scanners/git_scanner.py`)

Analyzes git commit history for leaked secrets using efficient pickaxe search.

**Features:**
- Searches git history for known secret patterns
- Uses `git log -S<term>` for 100x faster scanning than naive approaches
- Examines up to 100 commits by default (configurable)
- Scans added lines in diffs for pattern matches

**Configuration:**
```python
scan_git_history(root, max_commits=100)
```

### 2. Web Crawler (`scanners/web_crawler.py`)

Crawls web application endpoints to discover exposed sensitive paths and analyze client-side code.

**Features:**
- Discovers exposed `.env`, `.git/config`, backup files
- Analyzes JavaScript files for hardcoded secrets
- Extracts and scans source maps
- Checks HTTP headers and cookies for leaked secrets
- Detects catch-all responses (false positives)
- Multi-threaded crawling with process pool for regex scanning

**Configuration:**
```python
crawler = LocalCrawler(
    base="http://localhost:8000",
    timeout=6,
    max_pages=300,
    workers=8,
    max_js_size=500_000  # Skip large JS bundles
)
```

### 3. Browser Scanner (`scanners/browser_scanner.py`)

Uses Playwright to inspect browser runtime state and client-side storage.

**Features:**
- Extracts localStorage contents
- Extracts sessionStorage contents
- Retrieves all cookies
- Checks global variables (`window.__ENV`, `window.config`, `window.API_KEY`)

**Requirements:**
```bash
pip install playwright
python -m playwright install
```

**Usage:**
```python
playwright_inspect("http://localhost:8000")
```

### 4. Network Scanner (`scanners/network_scanner.py`)

Runs mitmproxy addon for deep packet inspection (Layer 2).

**Features:**
- Intercepts HTTP/HTTPS traffic at the proxy level
- Pattern matching on request/response bodies
- Security header validation
- Works alongside `inject_mitm_proxy.py` (Layer 1)

**Note:** Most users will use `inject_mitm_proxy.py` for MITM inspection. This module provides additional addon-based analysis.

## Output Format

### Audit Report (audit_report.json)

```json
{
  "timestamp": "2025-11-18T13:34:34.106644",
  "target": "http://localhost:8000",
  "stats": {
    "git_secrets": 0,
    "crawler_issues": 2,
    "browser_issues": 0,
    "mitm_proxied": 15,
    "mitm_bypassed": 3,
    "mitm_security_findings": 1
  },
  "severities": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 15
  },
  "findings": [
    {
      "type": "api_key_in_header",
      "severity": "HIGH",
      "timestamp": 1763494461,
      "timestamp_human": "2025-11-18 13:34:21",
      "description": "GROQ_API_KEY in Authorization header over HTTPS (expected for server-side API calls, review if unexpected)",
      "url": "https://api.groq.com/openai/v1/chat/completions",
      "client": "requests",
      "method": "post",
      "pattern": "GROQ_API_KEY",
      "header": "Authorization"
    }
  ]
}
```

### Traffic Log (mitm_traffic.ndjson)

NDJSON (newline-delimited JSON) format for append-only logging:

```json
{"ts": 1763494398, "timestamp": "2025-11-18 13:33:18", "stage": "mitm_outbound", "client": "requests", "method": "post", "url": "https://api.example.com/endpoint"}
{"ts": 1763494461, "timestamp": "2025-11-18 13:34:21", "stage": "security_finding", "severity": "HIGH", "type": "api_key_in_header", "pattern": "GROQ_API_KEY", "description": "...", "url": "...", "client": "requests", "method": "post", "header": "Authorization"}
```

**Stages:**
- `mitm_outbound`: Request sent through proxy
- `mitm_bypass`: Request bypassed proxy (OAuth, AWS, etc.)
- `security_finding`: Security issue detected

## Advanced Usage

### Custom Pattern Detection

Create a custom pattern file:

```bash
# Create custom-patterns.env
cat > custom-patterns.env << EOF
CUSTOM_API_KEY=custom_[0-9a-f]{32}
INTERNAL_TOKEN=int_tok_[A-Za-z0-9]{24}
EOF

# Edit config.py to load from custom file
# (Modify PATTERNS_FILE path in config.py)
```

### Integrating with CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Audit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: cp patterns.env.example patterns.env
      - run: python local_check.py --target http://localhost:8000 --root .
      - run: |
          if jq -e '.severities.CRITICAL > 0' audit_report.json; then
            echo "CRITICAL issues found!"
            exit 1
          fi
```

### Programmatic Usage

```python
from scanners import scan_git_history, LocalCrawler, playwright_inspect

# Git scanning
git_findings = scan_git_history("/path/to/repo", max_commits=100)

# Web crawling
crawler = LocalCrawler("http://localhost:8000", max_pages=200)
crawler.probe_common_paths()
crawler.crawl()
web_findings = crawler.findings

# Browser inspection
browser_data = playwright_inspect("http://localhost:8000")

# Combine results
all_findings = git_findings + web_findings
```

## Troubleshooting

### "No module named 'requests'"

```bash
pip install requests
```

### "patterns.env not found"

```bash
cp patterns.env.example patterns.env
```

### "playwright-not-installed"

```bash
pip install playwright
python -m playwright install
```

### "MITM proxy not loading patterns"

**Issue:** Backend shows `WARNING: patterns.env not found`

**Solution:**
```bash
# Verify patterns.env is in the same directory as inject_mitm_proxy.py
ls -la /path/to/backend/app/patterns.env

# If missing, copy it
cp patterns.env /path/to/backend/app/
```

### "MITM proxy not intercepting traffic"

**Issue:** No traffic logged in `mitm_traffic.ndjson`

**Solutions:**

1. Verify import is present and FIRST:
```python
import inject_mitm_proxy  # MUST BE FIRST
# ... other imports
python app.py
# Should see: "[MITM] Proxy active on http://127.0.0.1:8082"
```

2. Check proxy port matches:
```bash
# Scanner
python local_check.py --enable-mitm --mitm-port 8082

# Backend
export MITM_PROXY_PORT=8082
```

### "Permission denied during packet capture"

```bash
# Linux/Mac
sudo python local_check.py --enable-pcap

# Windows
# Run terminal as Administrator
```

### "Git scan is very slow"

This is normal for large repositories (100k+ commits). The tool limits to 100 commits by default. To adjust:

```python
# Modify scanners/git_scanner.py
scan_git_history(root, max_commits=50)  # Reduce commit limit
```

### "Too many false positives"

1. Adjust entropy threshold in `config.py`:
```python
ENTROPY_THRESHOLD = 4.0  # Higher = fewer false positives
```

2. Add exclusions for known patterns:
```python
# In config.py
EXCLUDE_PATTERNS = [
    r'test_api_key_123',  # Test keys
    r'example\.com',      # Example domains
]
```

3. Filter by severity in audit report:
```bash
# Only show CRITICAL issues
jq '.findings[] | select(.severity == "CRITICAL")' audit_report.json
```

## Security Considerations

### Testing Your Own Applications Only

This tool is designed for security testing of applications you own or have explicit permission to test. Unauthorized scanning may violate laws and terms of service.

### MITM Proxy Security

The MITM proxy **disables SSL verification** for testing purposes. This should only be used in development/testing environments, never in production.

**Do NOT:**
- Use MITM proxy in production environments
- Commit `inject_mitm_proxy.py` import to production code
- Share MITM proxy logs (may contain sensitive data)

**Best Practices:**
- Use environment variables to control MITM activation
- Keep `mitm_traffic.ndjson` and `audit_report.json` out of version control (add to `.gitignore`)
- Review and sanitize audit reports before sharing

### Pattern File Security

The `patterns.env` file is excluded from version control by default (`.gitignore`) to avoid triggering GitHub security alerts on pattern signatures.

**Do NOT:**
- Commit `patterns.env` to public repositories
- Include actual secret values in pattern files
- Share pattern files with untrusted parties

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Test your changes with multiple target applications
2. Update documentation for new features
3. Follow existing code style and structure
4. Add tests for new scanner modules
5. Ensure no secrets are committed in test files

## Disclaimer

This tool is provided for lawful security testing only. Users are responsible for ensuring they have proper authorization before scanning any application. The authors assume no liability for misuse or unauthorized access.

## Testing

### Quick Test Commands

```bash
# Run all tests (auto-detects Ollama)
python run_tests.py

# Run all tests including LLM (requires Ollama)
python run_tests.py --all

# Fast tests only (no LLM)
python run_tests.py --fast

# With coverage report
python run_tests.py --coverage

# Specific test file
python run_tests.py --file retriever
```

### Test Prerequisites

**Core tests** (no additional setup):
```bash
pip install pytest pytest-cov
pytest tests/ -v -k "not llm_client"
```

**LLM tests** (requires Ollama):
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh  # Linux/Mac
# Or download from https://ollama.com for Windows

# Pull model
ollama pull gemma3:1b

# Run all tests
pytest tests/ -v
```

### Test Coverage

| Component | Tests | Coverage |
|-----------|-------|----------|
| Knowledge Graph | ✅ 1 test | 100% |
| CWE Enrichment | ✅ 1 test | 100% |
| Database Normalizer | ✅ 5 tests | 95% |
| Graph Retriever | ✅ 8 tests | 100% |
| LLM Client | ✅ 8 tests | 85% |
| End-to-End Pipeline | ✅ 2 tests | Full flow |
| **Total** | **24 tests** | **~90%** |

See `tests/README.md` for detailed testing documentation.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing issues before creating new ones
- Provide detailed information (OS, Python version, error messages, steps to reproduce)
