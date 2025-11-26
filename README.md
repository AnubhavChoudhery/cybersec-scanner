# CyberSec Scanner# CyberSec Scanner



[![Tests](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/workflows/Tests/badge.svg)](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/actions)[![Tests](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/workflows/Tests/badge.svg)](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/actions)

[![Python](https://img.shields.io/pypi/pyversions/cybersec-scanner.svg)](https://pypi.org/project/cybersec-scanner/)[![Python](https://img.shields.io/pypi/pyversions/cybersec-scanner.svg)](https://pypi.org/project/cybersec-scanner/)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)



A comprehensive, modular security scanning toolkit for detecting secrets, vulnerabilities, and misconfigurations in Git repositories, web applications, and browser extensions. Features multi-scanner architecture, RAG-powered analysis with LLM integration, and both SDK and CLI interfaces.A comprehensive, modular security scanning toolkit for detecting secrets, vulnerabilities, and misconfigurations in Git repositories, web applications, and browser extensions. Features multi-scanner architecture, RAG-powered analysis, and both SDK and CLI interfaces.



> 🔒 **Use Responsibly**: This tool is for authorized security testing only. Always obtain proper permission before scanning applications you don't own.> 🔒 **Use Responsibly**: This tool is for authorized security testing only. Always obtain proper permission before scanning applications you don't own.



---## Table of Contents



## ✨ Features- [Features](#features)

- [Architecture](#architecture)

### 🔍 Multi-Scanner Architecture- [Installation](#installation)

- **Git Scanner**: Detect secrets in commit history using efficient pickaxe search- [Quick Start](#quick-start)

- **Web Crawler**: Discover exposed endpoints, analyze JavaScript files and source maps- [MITM Proxy Setup](#mitm-proxy-setup)

- **Browser Scanner**: Inspect localStorage, sessionStorage, cookies via Playwright- [Configuration](#configuration)

- **Network Scanner**: Real-time HTTPS traffic inspection with MITM proxy- [Usage](#usage)

- [Scanner Modules](#scanner-modules)

### 🧠 RAG-Powered Analysis- [Output Format](#output-format)

- **Knowledge Graph**: NetworkX-based relationship mapping between findings, files, and vulnerabilities- [Advanced Usage](#advanced-usage)

- **Semantic Search**: Vector-based retrieval for similar security patterns (optional hnswlib integration)- [Troubleshooting](#troubleshooting)

- **LLM Integration**: Natural language queries powered by Ollama (Gemma, Llama, Mistral, etc.)

- **CWE Enrichment**: Automatic mapping to Common Weakness Enumeration standards## ✨ Features



### 🎯 Detection Coverage (58+ Patterns)### 🔍 Multi-Scanner Architecture

- **Cloud Providers**: AWS, Azure, Google Cloud, DigitalOcean, Alibaba Cloud- **Git Scanner**: Detect secrets in commit history using efficient pickaxe search

- **AI/LLM Services**: OpenAI, Anthropic, Groq, Mistral, Hugging Face, Cohere- **Web Crawler**: Discover exposed endpoints, analyze JavaScript files and source maps

- **Payment Systems**: Stripe, PayPal, Square- **Browser Scanner**: Inspect localStorage, sessionStorage, cookies via Playwright

- **Development Platforms**: GitHub, GitLab, Bitbucket, npm- **Network Scanner**: Real-time HTTPS traffic inspection with MITM proxy

- **Databases**: MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch

- **Authentication**: JWT tokens, OAuth, Basic Auth, API keys### 🧠 RAG-Powered Analysis

- **Private Keys**: RSA, SSH, PGP, SSL certificates- **Knowledge Graph**: NetworkX-based relationship mapping between findings, files, and vulnerabilities

- **Custom Patterns**: Extensible regex-based system via `patterns.env`- **Semantic Search**: Vector-based retrieval for similar security patterns

- **LLM Integration**: Natural language queries powered by Ollama (Gemma, Llama, etc.)

### 🚀 Flexible Usage- **CWE Enrichment**: Automatic mapping to Common Weakness Enumeration

- **CLI Application**: Full-featured command-line interface with 7 commands

- **Python SDK**: Use scanners independently or together in your own code### 🎯 Detection Coverage

- **YAML Configuration**: Simple config files replace long CLI arguments- **58+ Built-in Patterns**: AWS, OpenAI, Stripe, GitHub, Azure, Google Cloud, databases, and more

- **Modular Design**: Import only what you need, lazy loading for optional dependencies- **Entropy Analysis**: High-entropy string detection for unknown secrets

- **Custom Patterns**: Extensible regex-based pattern system via `patterns.env`

---- **Contextual Severity**: Smart severity assignment based on exposure context



## 📦 Installation### 🚀 Flexible Usage

- **CLI Application**: Full-featured command-line interface with 7 commands

### From PyPI (Recommended)- **Python SDK**: Use scanners independently or together in your own code

- **YAML Configuration**: Simple config files replace long CLI arguments

```bash- **Modular Design**: Import only what you need, lazy loading for optional dependencies

pip install cybersec-scanner

```## 📦 Installation



### From Source### From PyPI (Recommended)



```bash```bash

git clone https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext.gitpip install cybersec-scanner

cd CyberSec_Chrome_Ext```

pip install -e .

```### From Source



### Optional Dependencies```bash

git clone https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext.git

```bashcd CyberSec_Chrome_Ext

# For vector search (RAG semantic features)pip install -e .

pip install "cybersec-scanner[vector]"```



# For development (testing, linting, type checking)### Optional Dependencies

pip install "cybersec-scanner[dev]"

```bash

# Install everything# For vector search (RAG features)

pip install "cybersec-scanner[vector,dev]"pip install cybersec-scanner[vector]

```

# For development

### System Requirementspip install cybersec-scanner[dev]

```

- **Python**: 3.8 or higher

- **Git**: For git history scanning (optional)### System Requirements

- **mitmproxy**: 10.0+ for HTTPS inspection (optional)

- **Playwright**: For browser inspection (optional)- Python 3.8 or higher

- **Ollama**: For LLM-powered queries (optional)- Git (for git history scanning)

- mitmproxy 10.0+ (for HTTPS inspection - optional)

---- Playwright (for browser inspection - optional)



## 🚀 Quick Start## 🚀 Quick Start



### 1. Install### CLI Usage



```bash```bash

pip install cybersec-scanner# Initialize configuration file

```cybersec-scanner init-config



### 2. Get Required Files# Scan a Git repository

cybersec-scanner scan-git /path/to/repo

**IMPORTANT**: You need `patterns.env` adjacent to your working directory:

# Scan a web application

```bashcybersec-scanner scan-web http://localhost:8000

# Download patterns file

curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env# Full scan with config file

cybersec-scanner scan --config my-config.yaml

# Or if you installed from source

cp /path/to/CyberSec_Chrome_Ext/patterns.env ./# Query findings with RAG

```cybersec-scanner query "What API keys were found?" --audit-report audit_report.json



### 3. Initialize Configuration# Check version

cybersec-scanner --version

```bash```

# Generate default config file

cybersec-scanner init-config### Python SDK Usage



# This creates: cybersec-config.yaml```python

```from cybersec_scanner import scan_git, scan_web, scan_all



### 4. Run Your First Scan# Scan a Git repository

findings = scan_git("/path/to/repo", max_commits=100)

```bashprint(f"Found {len(findings)} secrets in Git history")

# Scan a Git repository

cybersec-scanner scan-git /path/to/repo# Scan a web application

web_findings = scan_web("http://localhost:8000", max_pages=300)

# Scan a web application

cybersec-scanner scan-web http://localhost:8000# Full scan with custom config

config = {

# Full scan with config file    "git": {

cybersec-scanner scan --config cybersec-config.yaml        "enabled": True,

```        "repositories": ["/path/to/repo"],

        "max_commits": 100

### 5. View Results    },

    "web": {

```bash        "enabled": True,

# Results are saved to audit_report.json (default)        "target": "http://localhost:8000",

cat audit_report.json        "max_pages": 300

    },

# Or use jq for pretty output    "output": {

jq '.findings[] | select(.severity == "HIGH")' audit_report.json        "file": "security_report.json"

```    }

}

---

results = scan_all(config)

## 📋 Required Files Setup```



### patterns.env (REQUIRED)## 📋 Required Files



This file contains regex patterns for detecting secrets. It **must be in your working directory** (where you run the scanner).**IMPORTANT**: Before running scans, you need these files **adjacent to your working directory** (where you run the scanner):



**Download**:### 1. patterns.env (REQUIRED)

```bash

# From GitHubThis file contains regex patterns for detecting secrets. **Copy it from the repository root**:

curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env

```bash

# Or if installed from source# If you installed from source

cp patterns.env /your/project/directory/cp patterns.env /your/project/directory/

```

# If you installed from PyPI, download from GitHub

**Format** (example patterns included):curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env

```env```

AWS_ACCESS_KEY_ID=AKIA[0-9A-Z]{16}

OPENAI_API_KEY=sk-[a-zA-Z0-9]{20,}The file includes 58+ detection patterns for major providers:

STRIPE_SECRET_KEY=sk_live_[0-9a-zA-Z]{24,}```env

GITHUB_TOKEN=ghp_[0-9a-zA-Z]{36}AWS_ACCESS_KEY_ID=AKIA[0-9A-Z]{16}

MONGODB_URI=mongodb(\+srv)?:\/\/[^\s]{10,}OPENAI_API_KEY=sk-[a-zA-Z0-9]{20,}

JWT_TOKEN=eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}STRIPE_SECRET_KEY=sk_live_[0-9a-zA-Z]{24,}

```GITHUB_TOKEN=ghp_[0-9a-zA-Z]{36}

# ... and 54 more patterns

**Security Note**: Never commit actual secrets to this file! It's excluded from git by default.```



**Customization**:**Security Note**: This file is excluded from git by default to avoid triggering security scanners. Never commit actual secrets to this file!

```bash

# Add your own patterns```

echo "MY_CUSTOM_KEY=mycustom_[0-9a-f]{32}" >> patterns.envChrome_Ext/

```├── local_check.py              # Main orchestrator

├── config.py                   # Configuration and patterns

### inject_mitm_proxy.py (For MITM Features)├── utils.py                    # Utility functions

├── patterns.env                # Secret detection patterns (user-configured)

Only needed if you want MITM proxy for HTTPS traffic inspection.├── inject_mitm_proxy.py        # MITM proxy injection module

├── install_mitm_cert.py        # Certificate installation helper

**Download**:├── scanners/

```bash│   ├── git_scanner.py         # Git history analysis

# Download to your backend app directory│   ├── web_crawler.py         # HTTP endpoint scanning

cd /path/to/your/backend/app/│   ├── browser_scanner.py     # Playwright runtime inspection

curl -o inject_mitm_proxy.py https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/inject_mitm_proxy.py│   └── network_scanner.py     # MITM proxy traffic analysis

└── audit_report.json          # Output report (generated)

# Also copy patterns.env to the same location```

cp /path/to/patterns.env ./

```## Installation



**Integration** (add as FIRST import):### System Requirements

```python

# backend/app/main.py- Python 3.8 or higher

import inject_mitm_proxy  # MUST BE FIRST IMPORT- Git (for git history scanning)

- mitmproxy 10.0+ (for HTTPS inspection)

from fastapi import FastAPI- Modern web browser (for Playwright scanner)

# ... rest of your code

```### Required Dependencies



### Directory Structure Example```bash

pip install -r requirements.txt

``````

your-project/

├── patterns.env                    ← REQUIRED (in your working dir)If `requirements.txt` is not available, install manually:

├── cybersec-config.yaml            ← Optional config file

├── audit_report.json               ← Generated output```bash

├── test_scanner.py                 ← Your scanner scriptpip install requests colorama

│```

└── backend/                        ← Your backend app (for MITM)

    └── app/### Optional Dependencies

        ├── inject_mitm_proxy.py    ← Copy here for MITM

        ├── patterns.env            ← Copy here too#### For HTTPS Traffic Inspection

        ├── mitm_traffic.ndjson     ← Auto-generated```bash

        └── main.py                 ← Your app (imports inject_mitm_proxy)# Install mitmproxy

```pip install mitmproxy



---# Verify installation

mitmdump --version

## ⚙️ Configuration```



### YAML Configuration (Recommended)#### For Browser Runtime Inspection

```bash

Create `cybersec-config.yaml`:pip install playwright

python -m playwright install

```yaml```

# Git repository scanning

git:#### For Network Packet Capture (Advanced)

  enabled: true```bash

  repositories:pip install scapy

    - /path/to/repo1

    - /path/to/repo2# Windows: Install Npcap from https://npcap.com/

  max_commits: 100          # Limit commit history depth# Linux/Mac: May require libpcap

```

# Web application scanning

web:## Quick Start

  enabled: true

  target: http://localhost:8000### Initial Setup

  max_pages: 300            # Max pages to crawl

  timeout: 6                # HTTP timeout (seconds)1. **Clone or download the repository**



# Browser runtime inspection (requires playwright)2. **Set up pattern file** (REQUIRED before first run)

browser:

  enabled: false```bash

  target: http://localhost:8000# Copy the patterns file template

cp patterns.env.example patterns.env

# MITM proxy for HTTPS inspection

mitm:# The file includes 58+ detection patterns for major providers

  enabled: false# Edit patterns.env to customize or add patterns (optional)

  port: 8082```

  duration: 0               # 0 = manual stop with Ctrl+C

3. **Verify setup**

# Output settings

output:```bash

  file: audit_report.jsonpython -c "from config import KNOWN_PATTERNS; print(f'Loaded {len(KNOWN_PATTERNS)} patterns')"

  format: json```



# Pattern matching settingsExpected output: `Loaded 58 patterns` (or similar)

patterns:

  file: patterns.env### Basic Usage

  entropy_threshold: 3.5    # Shannon entropy for randomness detection

```bash

# RAG/LLM settings (optional)# Scan with default settings

rag:python local_check.py --target http://localhost:8000 --root /path/to/project

  enabled: false

  model: gemma3:1b          # Ollama model# Generate audit report

  vector_search: false      # Requires hnswlibcat audit_report.json

``````



**Generate default config**:## MITM Proxy Setup

```bash

cybersec-scanner init-configThe MITM (Man-in-the-Middle) proxy feature allows inspection of HTTPS traffic in real-time, including request/response headers and bodies.

```

### Prerequisites

### Environment Variables

1. **Install mitmproxy**

```bash

# MITM proxy port (default: 8082)```bash

export MITM_PROXY_PORT=9000pip install mitmproxy



# Patterns file location (default: ./patterns.env)# Verify installation

export PATTERNS_FILE=/custom/path/patterns.envmitmdump --version

```

# Output file (default: ./audit_report.json)

export AUDIT_REPORT=custom_report.json2. **Copy required files to your backend**

```

```bash

### CLI Arguments# From the Chrome_Ext directory

cp inject_mitm_proxy.py /path/to/your/backend/app/

Override config file with CLI args:cp patterns.env /path/to/your/backend/app/

```

```bash

cybersec-scanner scan \### Backend Integration

  --config my-config.yaml \

  --git-max-commits 200 \Add the following import as the **FIRST LINE** of your main application file:

  --web-target http://localhost:3000 \

  --web-max-pages 500 \**For FastAPI:**

  --output security_audit.json```python

```# backend/app/main.py

import inject_mitm_proxy  # MUST BE FIRST IMPORT

---

from fastapi import FastAPI

## 📖 CLI Usage# ... rest of your imports and code

```

### Commands Overview

**For Flask:**

```bash```python

cybersec-scanner [COMMAND] [OPTIONS]# backend/app.py

import inject_mitm_proxy  # MUST BE FIRST IMPORT

Commands:

  scan              Full scan with all enabled scannersfrom flask import Flask

  scan-git          Git repository scan only# ... rest of your imports and code

  scan-web          Web application scan only```

  query             Query findings with LLM (RAG)

  build-graph       Build knowledge graph from audit report**For Django:**

  init-config       Generate default config file```python

  --version         Show version# backend/manage.py or wsgi.py

  --help            Show help messageimport inject_mitm_proxy  # MUST BE FIRST IMPORT

```

# ... rest of Django setup

### 1. Full Scan```



```bash### Running with MITM Proxy

# Scan with config file

cybersec-scanner scan --config cybersec-config.yaml1. **Start your backend application**



# Scan with CLI args only (no config file)```bash

cybersec-scanner scan \# No environment variables needed - proxy is always enabled

  --git-enabled \# Just start your backend normally

  --git-repos /path/to/repo \uvicorn app.main:app --reload  # FastAPI example

  --web-enabled \```

  --web-target http://localhost:8000 \

  --output scan_results.jsonYou should see:

```

# Enable all scanners[MITM] Proxy active on http://127.0.0.1:8082

cybersec-scanner scan \[MITM] Bypass mode: AWS, OAuth, AI providers, payments, CDNs

  --config full-scan.yaml \[MITM] Patched libraries: requests, httpx, urllib, urllib3, aiohttp

  --browser-enabled \```

  --mitm-enabled

```2. **Run the security scanner**



### 2. Git Repository Scan```bash

# In a new terminal, run the scanner with MITM enabled

```bashpython local_check.py \

# Basic git scan  --target http://localhost:8000 \

cybersec-scanner scan-git /path/to/repo  --enable-mitm \

  --mitm-port 8082

# Limit commit depth (faster for large repos)```

cybersec-scanner scan-git /path/to/repo --max-commits 50

3. **Interact with your application** (make HTTP requests, use API endpoints, etc.)

# Multiple repositories

cybersec-scanner scan-git /repo1 /repo2 /repo34. **Stop the scanner** (Ctrl+C) to generate the audit report



# Custom output file5. **Review results**

cybersec-scanner scan-git /path/to/repo --output git_findings.json

``````bash

# View audit report

### 3. Web Application Scancat audit_report.json



```bash# View traffic log (raw NDJSON)

# Basic web scancat mitm_traffic.ndjson

cybersec-scanner scan-web http://localhost:8000```



# Limit crawl depth (faster for large sites)### MITM Proxy Detection Capabilities

cybersec-scanner scan-web http://localhost:8000 --max-pages 100

The MITM proxy inspects both requests and responses for security issues:

# Custom timeout and depth

cybersec-scanner scan-web http://localhost:8000 --timeout 10 --depth 500**Request-Side Detection:**

```- Credentials embedded in URLs (`user:pass@domain`)

- API keys in query parameters (`?api_key=xxx`)

### 4. RAG Query (Natural Language)- Basic Authentication headers (base64 credentials)

- API keys in Authorization headers (with context awareness)

Requires Ollama installed and running.- Plaintext passwords in request bodies (excludes bcrypt/argon2 hashes)

- Secrets matching any of the 58+ patterns

```bash

# Query findings with natural language**Response-Side Detection:**

cybersec-scanner query "What API keys were found in Git history?" \- Secrets leaked in response headers

  --audit-report audit_report.json- API keys in response bodies (JSON, HTML, JavaScript)

- Credentials in error messages

# Use specific LLM model- Database connection strings in stack traces

cybersec-scanner query "Show me all high severity findings" \- Debug information containing sensitive data

  --audit-report audit_report.json \

  --model gemma3:1b**Severity Levels:**

- `CRITICAL`: API keys in URLs, credentials over HTTP, plaintext passwords

# Query with context from knowledge graph- `HIGH`: API keys in headers over HTTPS (with expected auth disclaimer)

cybersec-scanner query "Which files have the most vulnerabilities?" \- `INFO`: Normal traffic logging (not a security issue)

  --audit-report audit_report.json \

  --use-graph### MITM Proxy Configuration

```

The `inject_mitm_proxy.py` module works automatically when imported. The only optional configuration is:

### 5. Build Knowledge Graph

```bash

```bash# Set custom MITM proxy port (default: 8082)

# Build graph from audit reportexport MITM_PROXY_PORT=9000

cybersec-scanner build-graph --audit-report audit_report.json```



# Custom output location**No other environment variables needed** - the proxy runs in full mode by default with intelligent domain bypass.

cybersec-scanner build-graph \

  --audit-report audit_report.json \### Domain Bypass Configuration

  --output my_graph.gpickle

```By default, the following domains bypass the MITM proxy to prevent authentication and SSL issues:



### 6. Initialize Configuration**OAuth Providers:**

- `accounts.google.com`, `oauth2.googleapis.com`, `login.microsoftonline.com`

```bash

# Create default config**AI Providers:**

cybersec-scanner init-config- `api.openai.com`, `openai.com`

- `api.anthropic.com`, `anthropic.com`

# Custom config name- `api.groq.com`, `groq.com`

cybersec-scanner init-config --output my-config.yaml- `api.mistral.ai`, `mistral.ai`

- `api-inference.huggingface.co`, `huggingface.co`

# This creates a YAML file with all available options- `api.cohere.ai`, `replicate.com`, `together.xyz`, `anyscale.com`, `perplexity.ai`

```

**AWS Services:**

### 7. Version- All `*.amazonaws.com` domains

- API Gateway, Lambda, S3, CloudFront

```bash

cybersec-scanner --version**Payment Providers:**

# Output: cybersec-scanner 0.1.0- `stripe.com`, `paypal.com`

```

**CDNs:**

---- `cloudflare.com`, `cloudfront.net`



## 🐍 Python SDK Usage**Localhost:**

- `127.0.0.1`, `localhost`

### Basic Scanning

To modify bypass rules, edit the `BYPASS_DOMAINS` and `AWS_SUFFIXES` sets in `inject_mitm_proxy.py`.

```python

from cybersec_scanner import scan_git, scan_web### Uninstalling MITM Proxy



# Git repository scanTo remove MITM proxy from your backend:

git_findings = scan_git(

    root="/path/to/repo",1. Remove or comment out the import:

    max_commits=100```python

)# import inject_mitm_proxy  # Disabled

```

for finding in git_findings:

    print(f"[{finding['severity']}] {finding['pattern']} in {finding['file']}")2. Restart your backend application



# Web application scanThe proxy is only active when the module is imported.

web_findings = scan_web(

    target="http://localhost:8000",## Configuration

    max_pages=300,

    timeout=6### Pattern File (patterns.env)

)

The `patterns.env` file contains regular expressions for detecting secrets. This file is excluded from version control to prevent triggering GitHub security alerts.

print(f"Crawled pages, found {len(web_findings)} issues")

```**Format:**

```

### Full Scan with Config DictionaryPATTERN_NAME=regex_pattern

```

```python

from cybersec_scanner import scan_all**Adding custom patterns:**

```bash

# Using config dictionary# Edit patterns.env

config = {nano patterns.env

    "git": {

        "enabled": True,# Add your pattern

        "repositories": ["/path/to/repo"],MY_CUSTOM_KEY=mykey_[0-9a-f]{32}

        "max_commits": 100

    },# Reload the scanner

    "web": {python local_check.py --target http://localhost:8000

        "enabled": True,```

        "target": "http://localhost:8000",

        "max_pages": 300,### Configuration File (config.py)

        "timeout": 6

    },**Entropy Threshold:**

    "browser": {```python

        "enabled": FalseENTROPY_THRESHOLD = 3.5  # Shannon entropy for randomness detection

    },```

    "mitm": {

        "enabled": True,**File Exclusions:**

        "port": 8082,```python

        "duration": 30  # Auto-stop after 30 secondsEXCLUDE_SUFFIXES = {

    },    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',

    "output": {    '.zip', '.tar', '.gz', '.pdf', '.exe', '.dll'

        "file": "audit_report.json",}

        "format": "json"```

    },

    "patterns": {**Probe Paths (for web crawler):**

        "file": "patterns.env",```python

        "entropy_threshold": 3.5PROBE_PATHS = [

    }    '/.env', '/.env.local', '/.env.production',

}    '/.git/config', '/.git/HEAD',

    '/config.php.bak', '/backup.sql'

# Run full scan]

results = scan_all(config)```



print(f"Total findings: {len(results['findings'])}")## Usage

print(f"Critical: {results['severities']['CRITICAL']}")

print(f"High: {results['severities']['HIGH']}")### Command-Line Options

```

```bash

### Using Individual Scanner Modulespython local_check.py [OPTIONS]

```

```python

from cybersec_scanner.scanners import GitScanner, WebCrawler, BrowserScanner**Core Options:**



# Git scanner| Option | Type | Default | Description |

git_scanner = GitScanner(root="/path/to/repo", max_commits=100)|--------|------|---------|-------------|

git_findings = git_scanner.scan()| `--target`, `-t` | URL | `http://localhost:8000` | Target application URL |

| `--root`, `-r` | Path | `.` | Repository root for static analysis |

# Web crawler| `--out`, `-o` | Path | `audit_report.json` | Output report filename |

crawler = WebCrawler(

    base="http://localhost:8000",**Scanner Options:**

    timeout=6,

    max_pages=300| Option | Type | Default | Description |

)|--------|------|---------|-------------|

crawler.crawl()| `--depth` | Integer | `300` | Maximum pages to crawl |

web_findings = crawler.get_findings()| `--enable-playwright` | Flag | `False` | Enable browser runtime inspection |

| `--enable-pcap` | Flag | `False` | Enable packet capture (requires root) |

# Browser scanner (requires playwright)| `--pcap-timeout` | Integer | `12` | Packet capture duration (seconds) |

browser_scanner = BrowserScanner(target="http://localhost:8000")

browser_data = browser_scanner.inspect()**MITM Proxy Options:**

print(f"localStorage keys: {list(browser_data['localStorage'].keys())}")

```| Option | Type | Default | Description |

|--------|------|---------|-------------|

### RAG System (Knowledge Graph + LLM)| `--enable-mitm` | Flag | `False` | Enable MITM proxy for HTTPS inspection |

| `--mitm-port` | Integer | `8082` | MITM proxy port |

```python| `--mitm-duration` | Integer | `0` | Auto-stop after N seconds (0 = manual) |

from cybersec_scanner.rag import KnowledgeGraph, GraphRetriever, LLMClient| `--mitm-traffic` | Path | Auto-detect | Custom path to traffic NDJSON file |

from cybersec_scanner import scan_git

### Usage Examples

# 1. Scan and get findings

findings = scan_git("/path/to/repo")**Basic scan:**

```bash

# 2. Build knowledge graphpython local_check.py --target http://localhost:8000 --root /path/to/project

graph = KnowledgeGraph()```



for finding in findings:**Full scan with all features:**

    graph.add_finding(```bash

        finding_id=finding['id'],python local_check.py \

        pattern=finding['pattern'],  --target http://localhost:3000 \

        severity=finding['severity'],  --root ~/myapp \

        file_path=finding['file'],  --enable-playwright \

        snippet=finding.get('snippet', '')  --enable-mitm \

    )  --depth 500 \

  --out security_report.json

# Save graph```

graph.save("knowledge_graph.gpickle")

**MITM-only scan (skip static/git):**

# 3. Query with graph retriever```bash

retriever = GraphRetriever(graph=graph)python local_check.py \

aws_findings = retriever.search_by_pattern("AWS_ACCESS_KEY")  --target http://localhost:8000 \

high_severity = retriever.search_by_severity("HIGH")  --enable-mitm \

  --mitm-duration 30

# 4. Natural language queries with LLM (requires Ollama)```

llm = LLMClient(model="gemma3:1b")

response = llm.query(**Custom traffic log location:**

    question="What are the most critical security issues?",```bash

    context=high_severitypython local_check.py \

)  --target http://localhost:8000 \

print(response)  --enable-mitm \

```  --mitm-traffic /custom/path/to/traffic.ndjson

```

### Database Operations

## Scanner Modules

```python

from cybersec_scanner.database import Database### 1. Git Scanner (`scanners/git_scanner.py`)



# Initialize databaseAnalyzes git commit history for leaked secrets using efficient pickaxe search.

db = Database(db_path="findings.db")

db.initialize_schema()**Features:**

- Searches git history for known secret patterns

# Store findings- Uses `git log -S<term>` for 100x faster scanning than naive approaches

for finding in findings:- Examines up to 100 commits by default (configurable)

    db.insert_finding(- Scans added lines in diffs for pattern matches

        pattern=finding['pattern'],

        severity=finding['severity'],**Configuration:**

        file_path=finding['file'],```python

        line_number=finding.get('line'),scan_git_history(root, max_commits=100)

        snippet=finding.get('snippet', '')```

    )

### 2. Web Crawler (`scanners/web_crawler.py`)

# Query findings

high_severity = db.get_findings_by_severity("HIGH")Crawls web application endpoints to discover exposed sensitive paths and analyze client-side code.

aws_keys = db.get_findings_by_pattern("AWS_ACCESS_KEY")

all_findings = db.get_all_findings()**Features:**

- Discovers exposed `.env`, `.git/config`, backup files

# Export to JSON- Analyzes JavaScript files for hardcoded secrets

import json- Extracts and scans source maps

with open("export.json", "w") as f:- Checks HTTP headers and cookies for leaked secrets

    json.dump(all_findings, f, indent=2)- Detects catch-all responses (false positives)

- Multi-threaded crawling with process pool for regex scanning

# Close connection

db.close()**Configuration:**

``````python

crawler = LocalCrawler(

---    base="http://localhost:8000",

    timeout=6,

## 🔌 MITM Proxy Setup (Advanced)    max_pages=300,

    workers=8,

MITM (Man-in-the-Middle) proxy inspects HTTPS traffic in real-time for secrets and vulnerabilities.    max_js_size=500_000  # Skip large JS bundles

)

### Prerequisites```



```bash### 3. Browser Scanner (`scanners/browser_scanner.py`)

# Install mitmproxy

pip install mitmproxyUses Playwright to inspect browser runtime state and client-side storage.



# Verify installation**Features:**

mitmdump --version- Extracts localStorage contents

```- Extracts sessionStorage contents

- Retrieves all cookies

### Setup Steps- Checks global variables (`window.__ENV`, `window.config`, `window.API_KEY`)



**1. Copy files to your backend**:**Requirements:**

```bash```bash

cd /path/to/your/backend/app/pip install playwright

curl -o inject_mitm_proxy.py https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/inject_mitm_proxy.pypython -m playwright install

curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env```

```

**Usage:**

**2. Integrate into your application** (add as FIRST import):```python

playwright_inspect("http://localhost:8000")

**FastAPI**:```

```python

# backend/app/main.py### 4. Network Scanner (`scanners/network_scanner.py`)

import inject_mitm_proxy  # MUST BE FIRST IMPORT

Runs mitmproxy addon for deep packet inspection (Layer 2).

from fastapi import FastAPI

**Features:**

app = FastAPI()- Intercepts HTTP/HTTPS traffic at the proxy level

- Pattern matching on request/response bodies

@app.get("/")- Security header validation

def read_root():- Works alongside `inject_mitm_proxy.py` (Layer 1)

    return {"Hello": "World"}

```**Note:** Most users will use `inject_mitm_proxy.py` for MITM inspection. This module provides additional addon-based analysis.



**Flask**:## Output Format

```python

# backend/app.py### Audit Report (audit_report.json)

import inject_mitm_proxy  # MUST BE FIRST IMPORT

```json

from flask import Flask{

  "timestamp": "2025-11-18T13:34:34.106644",

app = Flask(__name__)  "target": "http://localhost:8000",

  "stats": {

@app.route("/")    "git_secrets": 0,

def hello():    "crawler_issues": 2,

    return "Hello, World!"    "browser_issues": 0,

```    "mitm_proxied": 15,

    "mitm_bypassed": 3,

**Django**:    "mitm_security_findings": 1

```python  },

# backend/manage.py or wsgi.py  "severities": {

import inject_mitm_proxy  # MUST BE FIRST IMPORT    "CRITICAL": 0,

    "HIGH": 1,

# ... rest of Django code    "MEDIUM": 0,

```    "LOW": 0,

    "INFO": 15

### Running with MITM Proxy  },

  "findings": [

**Terminal 1** - Start backend:    {

```bash      "type": "api_key_in_header",

cd /path/to/backend      "severity": "HIGH",

python -m uvicorn app.main:app --reload  # FastAPI      "timestamp": 1763494461,

# OR      "timestamp_human": "2025-11-18 13:34:21",

python app.py  # Flask      "description": "GROQ_API_KEY in Authorization header over HTTPS (expected for server-side API calls, review if unexpected)",

# OR      "url": "https://api.groq.com/openai/v1/chat/completions",

python manage.py runserver  # Django      "client": "requests",

```      "method": "post",

      "pattern": "GROQ_API_KEY",

Expected output:      "header": "Authorization"

```    }

[MITM] Proxy active on http://127.0.0.1:8082  ]

[MITM] Bypass mode: AWS, OAuth, AI providers, payments, CDNs}

[MITM] Patched libraries: requests, httpx, urllib, urllib3, aiohttp```

[MITM] Traffic log: /path/to/backend/app/mitm_traffic.ndjson

```### Traffic Log (mitm_traffic.ndjson)



**Terminal 2** - Run scanner:NDJSON (newline-delimited JSON) format for append-only logging:

```bash

cybersec-scanner scan \```json

  --config my-config.yaml \{"ts": 1763494398, "timestamp": "2025-11-18 13:33:18", "stage": "mitm_outbound", "client": "requests", "method": "post", "url": "https://api.example.com/endpoint"}

  --mitm-enabled \{"ts": 1763494461, "timestamp": "2025-11-18 13:34:21", "stage": "security_finding", "severity": "HIGH", "type": "api_key_in_header", "pattern": "GROQ_API_KEY", "description": "...", "url": "...", "client": "requests", "method": "post", "header": "Authorization"}

  --mitm-port 8082```

```

**Stages:**

**Terminal 3** - Interact with app:- `mitm_outbound`: Request sent through proxy

```bash- `mitm_bypass`: Request bypassed proxy (OAuth, AWS, etc.)

# Make requests to trigger traffic- `security_finding`: Security issue detected

curl http://localhost:8000/api/users

# OR use Postman, browser, frontend, etc.## Advanced Usage

```

### Custom Pattern Detection

**Stop**: Press Ctrl+C in Terminal 2 to stop scanner and generate report.

Create a custom pattern file:

### MITM Detection Capabilities

```bash

**Request-Side Detection**:# Create custom-patterns.env

- ✅ Credentials embedded in URLs (`user:pass@domain`)cat > custom-patterns.env << EOF

- ✅ API keys in query parameters (`?api_key=xxx`)CUSTOM_API_KEY=custom_[0-9a-f]{32}

- ✅ Basic Authentication headers (base64 credentials)INTERNAL_TOKEN=int_tok_[A-Za-z0-9]{24}

- ✅ API keys in Authorization headersEOF

- ✅ Plaintext passwords in request bodies (excludes bcrypt/argon2 hashes)

- ✅ All 58+ patterns from `patterns.env`# Edit config.py to load from custom file

# (Modify PATTERNS_FILE path in config.py)

**Response-Side Detection**:```

- ✅ Secrets leaked in response headers

- ✅ API keys in response bodies (JSON, HTML, JavaScript)### Integrating with CI/CD

- ✅ Credentials in error messages

- ✅ Database connection strings in stack traces```yaml

- ✅ Debug information with sensitive data# .github/workflows/security-scan.yml

name: Security Audit

**Severity Levels**:on: [push, pull_request]

- `CRITICAL`: API keys in URLs, credentials over HTTP, plaintext passwordsjobs:

- `HIGH`: API keys in headers over HTTPS (with expected auth disclaimer)  scan:

- `INFO`: Normal traffic logging (not a security issue)    runs-on: ubuntu-latest

    steps:

### MITM Configuration      - uses: actions/checkout@v3

      - uses: actions/setup-python@v4

**Custom port**:        with:

```bash          python-version: '3.10'

export MITM_PROXY_PORT=9000      - run: pip install -r requirements.txt

python your_app.py      - run: cp patterns.env.example patterns.env

```      - run: python local_check.py --target http://localhost:8000 --root .

      - run: |

**Custom traffic log**:          if jq -e '.severities.CRITICAL > 0' audit_report.json; then

```bash            echo "CRITICAL issues found!"

# Scanner auto-detects log in backend directory            exit 1

# OR specify manually:          fi

cybersec-scanner scan --mitm-traffic /custom/path/traffic.ndjson```

```

### Programmatic Usage

### Domain Bypass (Auto-Skip)

```python

These domains automatically bypass the proxy to prevent auth/SSL issues:from scanners import scan_git_history, LocalCrawler, playwright_inspect



- **OAuth**: `accounts.google.com`, `login.microsoftonline.com`# Git scanning

- **AI/LLM**: `api.openai.com`, `api.anthropic.com`, `api.groq.com`, `api.mistral.ai`git_findings = scan_git_history("/path/to/repo", max_commits=100)

- **AWS**: All `*.amazonaws.com` domains

- **Payment**: `stripe.com`, `paypal.com`# Web crawling

- **CDN**: `cloudflare.com`, `cloudfront.net`crawler = LocalCrawler("http://localhost:8000", max_pages=200)

- **Localhost**: `127.0.0.1`, `localhost`crawler.probe_common_paths()

crawler.crawl()

Edit `BYPASS_DOMAINS` in `inject_mitm_proxy.py` to customize.web_findings = crawler.findings



### Uninstalling MITM# Browser inspection

browser_data = playwright_inspect("http://localhost:8000")

Remove or comment the import:

```python# Combine results

# import inject_mitm_proxy  # Disabledall_findings = git_findings + web_findings

``````



Restart your backend. The proxy is only active when imported.## Troubleshooting



---### "No module named 'requests'"



## 📊 Output Formats```bash

pip install requests

### Audit Report (JSON)```



`audit_report.json` contains all findings with metadata:### "patterns.env not found"



```json```bash

{cp patterns.env.example patterns.env

  "timestamp": "2025-11-27T10:30:15.123456",```

  "target": "http://localhost:8000",

  "stats": {### "playwright-not-installed"

    "git_secrets": 3,

    "crawler_issues": 12,```bash

    "browser_issues": 0,pip install playwright

    "mitm_proxied": 45,python -m playwright install

    "mitm_bypassed": 8,```

    "mitm_security_findings": 2

  },### "MITM proxy not loading patterns"

  "severities": {

    "CRITICAL": 1,**Issue:** Backend shows `WARNING: patterns.env not found`

    "HIGH": 4,

    "MEDIUM": 7,**Solution:**

    "LOW": 3,```bash

    "INFO": 45# Verify patterns.env is in the same directory as inject_mitm_proxy.py

  },ls -la /path/to/backend/app/patterns.env

  "findings": [

    {# If missing, copy it

      "type": "api_key_in_url",cp patterns.env /path/to/backend/app/

      "severity": "CRITICAL",```

      "timestamp": 1732705815,

      "timestamp_human": "2025-11-27 10:30:15",### "MITM proxy not intercepting traffic"

      "description": "AWS_ACCESS_KEY_ID found in URL query parameter",

      "url": "https://api.example.com/endpoint?key=AKIAIOSFODNN7EXAMPLE",**Issue:** No traffic logged in `mitm_traffic.ndjson`

      "pattern": "AWS_ACCESS_KEY_ID",

      "location": "url_query",**Solutions:**

      "file": null,

      "line": null,1. Verify import is present and FIRST:

      "snippet": "?key=AKIAIOSFODNN7EXAMPLE"```python

    },import inject_mitm_proxy  # MUST BE FIRST

    {# ... other imports

      "type": "secret_in_git_history",python app.py

      "severity": "HIGH",# Should see: "[MITM] Proxy active on http://127.0.0.1:8082"

      "commit": "abc123def456",```

      "file": "config/database.yml",

      "line": 12,2. Check proxy port matches:

      "pattern": "MONGODB_URI",```bash

      "snippet": "mongodb://admin:password@localhost:27017/db"# Scanner

    }python local_check.py --enable-mitm --mitm-port 8082

  ]

}# Backend

```export MITM_PROXY_PORT=8082

```

### Traffic Log (NDJSON)

### "Permission denied during packet capture"

`mitm_traffic.ndjson` logs MITM proxy activity (newline-delimited JSON):

```bash

```json# Linux/Mac

{"ts": 1732705800, "timestamp": "2025-11-27 10:30:00", "stage": "mitm_outbound", "client": "requests", "method": "post", "url": "https://api.example.com/endpoint"}sudo python local_check.py --enable-pcap

{"ts": 1732705801, "timestamp": "2025-11-27 10:30:01", "stage": "security_finding", "severity": "HIGH", "type": "api_key_in_header", "pattern": "OPENAI_API_KEY", "description": "OpenAI API key in Authorization header", "url": "https://api.openai.com/v1/chat/completions", "client": "httpx", "method": "post", "header": "Authorization"}

{"ts": 1732705802, "timestamp": "2025-11-27 10:30:02", "stage": "mitm_bypass", "reason": "oauth_domain", "url": "https://accounts.google.com/oauth/token"}# Windows

```# Run terminal as Administrator

```

**Stages**:

- `mitm_outbound`: Request sent through proxy### "Git scan is very slow"

- `mitm_bypass`: Request bypassed proxy (OAuth, AWS, etc.)

- `security_finding`: Security issue detectedThis is normal for large repositories (100k+ commits). The tool limits to 100 commits by default. To adjust:



### Querying Results```python

# Modify scanners/git_scanner.py

```bashscan_git_history(root, max_commits=50)  # Reduce commit limit

# High severity only```

jq '.findings[] | select(.severity == "HIGH")' audit_report.json

### "Too many false positives"

# Count by severity

jq '.severities' audit_report.json1. Adjust entropy threshold in `config.py`:

```python

# Group by patternENTROPY_THRESHOLD = 4.0  # Higher = fewer false positives

jq '.findings | group_by(.pattern) | map({pattern: .[0].pattern, count: length})' audit_report.json```



# Git findings only2. Add exclusions for known patterns:

jq '.findings[] | select(.type == "secret_in_git_history")' audit_report.json```python

# In config.py

# MITM findings onlyEXCLUDE_PATTERNS = [

jq '.findings[] | select(.type | contains("mitm"))' audit_report.json    r'test_api_key_123',  # Test keys

```    r'example\.com',      # Example domains

]

---```



## 🧪 Testing3. Filter by severity in audit report:

```bash

### Run Tests# Only show CRITICAL issues

jq '.findings[] | select(.severity == "CRITICAL")' audit_report.json

```bash```

# Run all tests

pytest## Security Considerations



# Run with coverage### Testing Your Own Applications Only

pytest --cov=cybersec_scanner --cov-report=html

This tool is designed for security testing of applications you own or have explicit permission to test. Unauthorized scanning may violate laws and terms of service.

# Run specific test file

pytest tests/test_git_scanner.py -v### MITM Proxy Security



# Run fast tests (skip LLM tests)The MITM proxy **disables SSL verification** for testing purposes. This should only be used in development/testing environments, never in production.

pytest -m "not llm"

```**Do NOT:**

- Use MITM proxy in production environments

### Test Coverage- Commit `inject_mitm_proxy.py` import to production code

- Share MITM proxy logs (may contain sensitive data)

| Component | Tests | Coverage |

|-----------|-------|----------|**Best Practices:**

| Knowledge Graph | ✅ | 100% |- Use environment variables to control MITM activation

| CWE Enrichment | ✅ | 100% |- Keep `mitm_traffic.ndjson` and `audit_report.json` out of version control (add to `.gitignore`)

| Database | ✅ | 95% |- Review and sanitize audit reports before sharing

| Graph Retriever | ✅ | 100% |

| LLM Client | ✅ | 85% |### Pattern File Security

| Scanners | ✅ | 80% |

| **Total** | **25+ tests** | **~90%** |The `patterns.env` file is excluded from version control by default (`.gitignore`) to avoid triggering GitHub security alerts on pattern signatures.



---**Do NOT:**

- Commit `patterns.env` to public repositories

## 🔧 Troubleshooting- Include actual secret values in pattern files

- Share pattern files with untrusted parties

### "patterns.env not found"

## License

```bash

# Download patterns fileMIT License - See LICENSE file for details.

curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env

## Contributing

# Verify it's in your working directory

ls patterns.envContributions are welcome! Please follow these guidelines:

```

1. Test your changes with multiple target applications

### "No module named 'cybersec_scanner'"2. Update documentation for new features

3. Follow existing code style and structure

```bash4. Add tests for new scanner modules

# Reinstall package5. Ensure no secrets are committed in test files

pip install --upgrade cybersec-scanner

## Disclaimer

# Or if from source

cd CyberSec_Chrome_ExtThis tool is provided for lawful security testing only. Users are responsible for ensuring they have proper authorization before scanning any application. The authors assume no liability for misuse or unauthorized access.

pip install -e .

```## Testing



### "MITM proxy not loading patterns"### Quick Test Commands



```bash```bash

# Verify patterns.env is in backend app directory# Run all tests (auto-detects Ollama)

ls /path/to/backend/app/patterns.envpython run_tests.py



# If missing, copy it# Run all tests including LLM (requires Ollama)

cp patterns.env /path/to/backend/app/python run_tests.py --all

```

# Fast tests only (no LLM)

### "MITM proxy not intercepting traffic"python run_tests.py --fast



1. **Verify import is FIRST**:# With coverage report

```pythonpython run_tests.py --coverage

import inject_mitm_proxy  # Must be line 1

# ... other imports# Specific test file

```python run_tests.py --file retriever

```

2. **Check port matches**:

```bash### Test Prerequisites

# Backend

export MITM_PROXY_PORT=8082**Core tests** (no additional setup):

```bash

# Scannerpip install pytest pytest-cov

cybersec-scanner scan --mitm-port 8082pytest tests/ -v -k "not llm_client"

``````



3. **Check proxy is active**:**LLM tests** (requires Ollama):

Backend should print: `[MITM] Proxy active on http://127.0.0.1:8082````bash

# Install Ollama

### "Git scan is slow"curl -fsSL https://ollama.com/install.sh | sh  # Linux/Mac

# Or download from https://ollama.com for Windows

```bash

# Limit commit depth# Pull model

cybersec-scanner scan-git /repo --max-commits 50ollama pull gemma3:1b



# Or in config# Run all tests

git:pytest tests/ -v

  max_commits: 50```

```

### Test Coverage

### "Too many false positives"

| Component | Tests | Coverage |

1. **Adjust entropy threshold** (in config or `config.py`):|-----------|-------|----------|

```yaml| Knowledge Graph | ✅ 1 test | 100% |

patterns:| CWE Enrichment | ✅ 1 test | 100% |

  entropy_threshold: 4.0  # Higher = fewer false positives| Database Normalizer | ✅ 5 tests | 95% |

```| Graph Retriever | ✅ 8 tests | 100% |

| LLM Client | ✅ 8 tests | 85% |

2. **Filter by severity**:| End-to-End Pipeline | ✅ 2 tests | Full flow |

```bash| **Total** | **24 tests** | **~90%** |

jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' audit_report.json

```See `tests/README.md` for detailed testing documentation.



### "Playwright not installed"## Support



```bashFor issues, questions, or contributions:

pip install playwright- Open an issue on GitHub

python -m playwright install- Review existing issues before creating new ones

```- Provide detailed information (OS, Python version, error messages, steps to reproduce)


### "LLM query fails"

```bash
# Install Ollama
# Linux/Mac:
curl -fsSL https://ollama.com/install.sh | sh

# Windows: Download from https://ollama.com

# Pull model
ollama pull gemma3:1b

# Verify Ollama is running
ollama list
```

---

## 🛡️ Security Considerations

### Authorized Testing Only

This tool is designed for security testing of **applications you own or have explicit permission to test**. Unauthorized scanning may violate laws and terms of service.

### MITM Proxy Security

The MITM proxy **disables SSL verification** for testing purposes. **NEVER use in production environments**.

**Do NOT**:
- ❌ Use MITM proxy in production
- ❌ Commit `inject_mitm_proxy.py` import to production code
- ❌ Share MITM logs (may contain sensitive data)

**Best Practices**:
- ✅ Use environment variables to control MITM activation
- ✅ Add `mitm_traffic.ndjson` to `.gitignore`
- ✅ Review and sanitize reports before sharing
- ✅ Delete MITM logs after testing

### Pattern File Security

The `patterns.env` file is excluded from version control by default to avoid triggering GitHub security alerts.

**Do NOT**:
- ❌ Commit `patterns.env` to public repositories
- ❌ Include actual secret values in pattern files
- ❌ Share pattern files with untrusted parties

---

## 📚 Advanced Topics

### Custom Pattern Detection

Add custom patterns to `patterns.env`:

```bash
# Edit patterns.env
nano patterns.env

# Add patterns
MY_API_KEY=myapi_[0-9a-f]{32}
INTERNAL_TOKEN=int_tok_[A-Za-z0-9]{24}
```

### CI/CD Integration

**GitHub Actions**:
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install scanner
        run: pip install cybersec-scanner
      
      - name: Download patterns
        run: curl -o patterns.env https://raw.githubusercontent.com/AnubhavChoudhery/CyberSec_Chrome_Ext/main/patterns.env
      
      - name: Run scan
        run: cybersec-scanner scan-git . --output scan_results.json
      
      - name: Check for critical issues
        run: |
          CRITICAL=$(jq '.severities.CRITICAL' scan_results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL critical security issues"
            exit 1
          fi
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan_results.json
```

### Docker Container

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install scanner
RUN pip install cybersec-scanner

# Copy patterns file
COPY patterns.env /app/

# Entry point
ENTRYPOINT ["cybersec-scanner"]
CMD ["--help"]
```

**Usage**:
```bash
# Build
docker build -t cybersec-scanner .

# Run scan (mount your repo)
docker run -v $(pwd):/scan cybersec-scanner scan-git /scan
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "🔍 Running security scan..."

# Scan staged files
cybersec-scanner scan-git . --max-commits 1 --output /tmp/scan.json

# Check for critical issues
CRITICAL=$(jq '.severities.CRITICAL' /tmp/scan.json)
if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Critical security issues found in commit"
    echo "Review /tmp/scan.json for details"
    exit 1
fi

echo "✅ Security scan passed"
```

---

## 📖 Further Reading

- **CLI Documentation**: Run `cybersec-scanner --help` for command details
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for version history
- **Manual Releases**: See [MANUAL_RELEASE.md](MANUAL_RELEASE.md) for release process

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Add tests for your changes
4. Run tests (`pytest`)
5. Commit (`git commit -m "feat: add my feature"`)
6. Push (`git push origin feat/my-feature`)
7. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is provided for **lawful security testing only**. Users are responsible for ensuring they have proper authorization before scanning any application. The authors assume no liability for misuse or unauthorized access.

---

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AnubhavChoudhery/CyberSec_Chrome_Ext/discussions)
- **Email**: Open an issue for support inquiries

---

**Made with ❤️ by the CyberSec Scanner team**
