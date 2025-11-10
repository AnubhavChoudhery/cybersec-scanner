# Local Security Audit Tool

A comprehensive security scanner for localhost applications that detects hardcoded secrets, exposed endpoints, and configuration vulnerabilities.

## Project Structure

```
Chrome_Ext/
├── local_check.py              # Main entry point - orchestrates all scanners
├── config.py                   # Configuration constants and regex patterns
├── utils.py                    # Core utility functions (entropy, scoring, etc.)
├── scanners/                   # Specialized scanner modules
│   ├── __init__.py            # Package initialization
│   ├── static_scanner.py      # File-based secret detection
│   ├── git_scanner.py         # Git history analysis
│   ├── web_crawler.py         # HTTP endpoint scanning
│   ├── browser_scanner.py     # Playwright runtime inspection
│   └── network_scanner.py     # Packet capture analysis
└── local_check_backup.py      # Backup of original monolithic version
```

## Quick Start

### Installation

```bash
# Required dependencies
pip install requests

# Optional dependencies
pip install playwright scapy
python -m playwright install  # Install browser binaries
```

### Initial Setup

**IMPORTANT: Set up pattern file before first use**

```bash
# 1. Copy the example patterns file
cp patterns.env.example patterns.env

# 2. (Optional) Edit patterns.env to add custom patterns
# The file includes 99+ detection patterns for:
# - OpenAI, Anthropic, Groq, Cohere, Hugging Face
# - AWS, Google Cloud, Azure
# - Stripe, PayPal, Square
# - GitHub, GitLab, Bitbucket
# - Slack, Discord, Telegram
# - MongoDB, PostgreSQL, Redis
# - And many more...

# 3. Verify setup
python -c "from config import KNOWN_PATTERNS; print(f'Loaded {len(KNOWN_PATTERNS)} patterns')"
```

**Why patterns.env?**
- Keeps sensitive regex patterns out of version control
- Prevents GitHub security alerts on pattern signatures
- Allows customization without modifying source code
- patterns.env is automatically excluded via .gitignore

### Basic Usage

```bash
# Basic scan
python local_check.py --target http://localhost:8000 --root .

# Full scan with all features
python local_check.py -t http://localhost:3000 -r ./myapp --enable-playwright --enable-pcap

# Custom output and depth
python local_check.py -t http://localhost:5000 --out my_report.json --depth 100
```

## Command-Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--target` | `-t` | `http://localhost:8000` | Target URL to scan |
| `--root` | `-r` | `.` | Repository root for static analysis |
| `--out` | `-o` | `audit_report.json` | Output report filename |
| `--depth` | | `300` | Maximum pages to crawl |
| `--enable-playwright` | | `False` | Enable browser runtime checks |
| `--enable-pcap` | | `False` | Enable packet capture (requires root/admin) |
| `--pcap-timeout` | | `12` | Packet capture duration in seconds |
| `--enable-mitm` | | `False` | Enable MITM proxy for HTTPS inspection |
| `--mitm-port` | | `8080` | Port for MITM proxy |
| `--mitm-timeout` | | `0` | MITM duration (0 = interactive/Ctrl+C) |
| `--auto-install-cert` | | `False` | Auto-install MITM certificate (requires admin/sudo) |

## MITM Proxy for HTTPS Inspection

The MITM (Man-in-the-Middle) proxy feature allows you to inspect HTTPS traffic from your application in real-time.

### Quick Start

**Windows (as Administrator):**
```bash
python local_check.py --target http://localhost:8501 --enable-mitm --auto-install-cert
```

**Linux/Mac:**
```bash
sudo python local_check.py --target http://localhost:8501 --enable-mitm --auto-install-cert
```

This will:
1. ✅ Automatically install the mitmproxy certificate
2. ✅ Start the proxy on port 8080
3. ✅ Show instructions for configuring your browser
4. ✅ Capture and analyze all HTTP/HTTPS traffic

### Manual Certificate Installation

If automatic installation doesn't work:

1. Start the scanner:
   ```bash
   python local_check.py --target http://localhost:8501 --enable-mitm --mitm-port 8082
   ```

2. Configure browser proxy to `127.0.0.1:8082`

3. Visit `http://mitm.it` and install certificate

4. Interact with your application

**See [`MITM_SETUP_GUIDE.md`](MITM_SETUP_GUIDE.md) for detailed instructions**

### What Gets Detected

- 🔍 **Passwords in plaintext** - Credentials sent without proper encryption
- 🔍 **Tokens in URLs** - API keys in query parameters (insecure practice)
- 🔍 **Credit card numbers** - PCI-sensitive data exposure
- 🔍 **API keys and secrets** - Leaked credentials in requests/responses
- 🔍 **Missing security headers** - HSTS, CSP, X-Frame-Options, etc.
- 🔍 **All custom patterns** - From your `patterns.env` file

### Standalone Certificate Installer

Install certificate separately:
```bash
# Start mitmproxy first
mitmdump -p 8082

# In another terminal (as Administrator/sudo)
python install_mitm_cert.py --port 8082
```

## Scanner Modules

### 1. Static Scanner (`scanners/static_scanner.py`)
- Recursively scans files for hardcoded secrets
- Uses entropy analysis and pattern matching
- Identifies API keys, tokens, passwords in source code
- **Configuration**: `config.py` - `EXCLUDE_SUFFIXES`, `KNOWN_PATTERNS`

### 2. Git Scanner (`scanners/git_scanner.py`)
- Analyzes git commit history for leaked secrets
- Uses efficient pickaxe search (`git log -S`)
- Finds secrets that were committed and later removed
- **Performance**: 100x faster than naive commit-by-commit scanning

### 3. Web Crawler (`scanners/web_crawler.py`)
- Crawls localhost applications for exposed endpoints
- Analyzes JavaScript files and source maps
- Checks HTTP headers for leaked secrets
- Probes common sensitive paths (`.env`, `.git/config`, etc.)
- **Configuration**: `config.py` - `PROBE_PATHS`

### 4. Browser Scanner (`scanners/browser_scanner.py`)
- Uses Playwright to inspect runtime browser state
- Checks localStorage, sessionStorage, cookies
- Analyzes global JavaScript variables
- **Requires**: `pip install playwright && python -m playwright install`

### 5. Network Scanner (`scanners/network_scanner.py`)
- Captures network packets to detect plaintext HTTP traffic
- Identifies secrets transmitted over unencrypted connections
- **Requires**: Root/Administrator privileges + Scapy
- **Limitation**: Cannot decrypt HTTPS traffic

## Configuration

### Pattern Management

The tool uses `patterns.env` to store secret detection patterns. This keeps sensitive regex signatures out of version control.

**Setup:**
```bash
# Copy template
cp patterns.env.example patterns.env

# Edit to customize (optional)
nano patterns.env  # or use your favorite editor
```

**Default Patterns (99+ included):**
- **AI/ML**: OpenAI, Anthropic (Claude), Groq, Cohere, Hugging Face, Replicate
- **Cloud**: AWS, Google Cloud, Azure, Heroku, Cloudflare
- **Payments**: Stripe, PayPal, Square, Coinbase
- **Databases**: MongoDB, PostgreSQL, MySQL, Redis, Supabase
- **Dev Tools**: GitHub, GitLab, NPM, PyPI, Docker Hub
- **Communication**: Slack, Discord, Telegram, Twilio, SendGrid
- **Monitoring**: DataDog, Sentry, New Relic
- **And many more...**

### Scoring Thresholds
```python
MIN_LEN = 20              # Minimum string length for secrets
ENTROPY_THRESHOLD = 3.5   # Shannon entropy threshold
SCORE_THRESHOLD = 2       # Minimum score to report finding
```

### File Exclusions
```python
# Edit config.py
EXCLUDE_SUFFIXES = {'.png', '.jpg', '.zip', ...}
```

### Probe Paths
```python
# Edit config.py
PROBE_PATHS = [
    "/.env", "/.git/config", "/config.php.bak",
    # Add custom paths here
]
```

## Output Format

The tool generates a JSON report with:

```json
{
  "meta": {
    "root": "/path/to/project",
    "target": "http://localhost:8000",
    "time": "Wed Nov 6 2025",
    "playwright": false,
    "pcap": false
  },
  "findings": [
    {
      "type": "static_literal",
      "file": "/path/to/file.js",
      "snippet": "sk_live_abc123...",
      "score": 6,
      "reasons": ["len=32", "entropy=4.2", "pattern=Stripe Secret"],
      "entropy": 4.2
    }
  ],
  "summary": {
    "static_literal": 12,
    "git_match": 3,
    "exposed_path": 2
  }
}
```

## Extending the Tool

### Adding a New Pattern

Edit `config.py`:
```python
KNOWN_PATTERNS = {
    # ... existing patterns ...
    "My Custom Key": re.compile(r"mykey_[0-9a-f]{32}"),
}
```

### Creating a New Scanner

1. Create `scanners/my_scanner.py`
2. Implement your scanning logic
3. Export function in `scanners/__init__.py`
4. Call it from `local_check.py` main function

Example:
```python
# scanners/my_scanner.py
def scan_my_stuff(target):
    findings = []
    # Your scanning logic here
    return findings

# scanners/__init__.py
from .my_scanner import scan_my_stuff
__all__ = [..., 'scan_my_stuff']

# local_check.py
from scanners import scan_my_stuff
# Call it in main()
my_findings = scan_my_stuff(target)
report["findings"].extend(my_findings)
```

## Module Details

### `config.py`
- All configuration constants
- Regex patterns for secret detection
- File exclusions and probe paths

### `utils.py`
- `shannon_entropy()` - Calculate string randomness
- `is_text_file()` - Detect text vs binary files
- `extract_string_literals()` - Parse quoted strings from code
- `score_literal()` - Score strings for secret likelihood

### `scanners/`
Each scanner is independent and can be used standalone:
```python
from scanners import scan_files, scan_git_history, LocalCrawler

# Use individual scanners
findings = scan_files("/path/to/project")
git_findings = scan_git_history("/path/to/repo")

crawler = LocalCrawler("http://localhost:3000")
crawler.crawl()
```

## Troubleshooting

### "requests library not found"
```bash
pip install requests
```

### "playwright-not-installed"
```bash
pip install playwright
python -m playwright install
```

### "scapy-not-installed"
```bash
pip install scapy
# Windows: Also install Npcap from https://npcap.com/
```

### "Permission denied during packet capture"
```bash
# Linux/Mac
sudo python local_check.py --enable-pcap

# Windows
# Run terminal as Administrator
```

### Git scan is slow
- This is normal for large repos (100k+ commits)
- The tool limits to 20 commits per pattern
- Consider scanning specific branches: modify `git_scanner.py`

## License

MIT License - See original project documentation

## Disclaimer

This tool is intended for lawful security testing of YOUR OWN applications only. Do not use it to scan applications you don't own or have permission to test.
