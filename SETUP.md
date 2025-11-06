# Setup Guide

## Initial Setup (First Time)

### 1. Install Dependencies

```bash
# Required
pip install requests

# Optional (for full functionality)
pip install playwright scapy

# If using Playwright
python -m playwright install
```

### 2. Configure Pattern Detection

**Copy the pattern template:**
```bash
cp patterns.env.example patterns.env
```

This creates your local `patterns.env` file with 99+ secret detection patterns including:
- OpenAI, Anthropic, Groq, Cohere
- AWS, Google Cloud, Azure
- GitHub, GitLab, Bitbucket
- Stripe, PayPal, Square
- Slack, Discord, Telegram
- MongoDB, PostgreSQL, Redis
- And many more...

**Verify setup:**
```bash
python -c "from config import KNOWN_PATTERNS; print(f'✓ Loaded {len(KNOWN_PATTERNS)} patterns')"
```

Expected output:
```
✓ Loaded 99 secret detection patterns from patterns.env
✓ Loaded 99 patterns
```

### 3. Test the Scanner

```bash
# Basic test (dry run)
python local_check.py --help

# Scan current directory
python local_check.py --target http://localhost:8000 --root . --depth 10
```

## Why patterns.env?

### The Problem
GitHub and other git platforms scan repositories for sensitive data. They will flag **even the regex patterns** for API keys as security risks.

Example - This triggers alerts:
```python
# ❌ GitHub sees this pattern and flags it
OPENAI_PATTERN = r"sk-[a-zA-Z0-9]{48}"
```

### The Solution
We store patterns in a separate `.env` file that's excluded from version control:

```bash
# ✅ Safe - patterns.env is in .gitignore
OPENAI_API_KEY=sk-[a-zA-Z0-9]{48}
```

```python
# ✅ Safe - config.py loads patterns dynamically
KNOWN_PATTERNS = load_patterns_from_env()
```

### Files Excluded from Git
- `patterns.env` - Your active pattern file (DO NOT COMMIT)
- `*.key`, `*.pem` - Any key files
- `.env*` - All environment files
- `*_report.json` - Scan outputs

### Files Included in Git
- `patterns.env.example` - Template (safe to commit)
- `config.py` - Pattern loader (no actual patterns)
- All scanner modules

## Customization

### Add Custom Patterns

Edit `patterns.env`:
```bash
# Add at the end
MY_COMPANY_API=mycompany_[a-z0-9]{40}
INTERNAL_TOKEN=int_tok_[A-Za-z0-9]{32}
```

### Adjust Sensitivity

Edit `config.py`:
```python
# Make scanner less sensitive (fewer false positives)
ENTROPY_THRESHOLD = 4.0  # Default: 3.5
SCORE_THRESHOLD = 3      # Default: 2

# Make scanner more sensitive (catch more secrets, more false positives)
ENTROPY_THRESHOLD = 3.0
SCORE_THRESHOLD = 1
```

### Exclude File Types

Edit `config.py`:
```python
EXCLUDE_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif',  # Images
    '.zip', '.tar', '.gz',            # Archives
    '.db', '.sqlite',                 # Databases
    '.pdf', '.doc', '.docx',          # Documents (add these)
    # Add more as needed
}
```

### Add Probe Paths

Edit `config.py`:
```python
PROBE_PATHS = [
    "/.env",
    "/.git/config",
    # Add custom paths for your stack
    "/wp-config.php",        # WordPress
    "/settings.py",          # Django
    "/application.yml",      # Spring Boot
]
```

## Troubleshooting

### "patterns.env not found"
```bash
# Solution: Copy the template
cp patterns.env.example patterns.env
```

The tool will work with fallback patterns but won't detect as many secret types.

### "Import error: No module named 'requests'"
```bash
pip install requests
```

### "playwright-not-installed"
```bash
pip install playwright
python -m playwright install
```

### "Permission denied" (packet capture)
```bash
# Linux/Mac
sudo python local_check.py --enable-pcap

# Windows
# Right-click terminal > "Run as Administrator"
```

### Patterns not loading
```bash
# Check file exists
ls -la patterns.env

# Check file format (must be KEY=VALUE)
head -n 20 patterns.env

# Test loading
python -c "from config import KNOWN_PATTERNS; print(len(KNOWN_PATTERNS))"
```

## Advanced Usage

### Scan Multiple Projects
```bash
# Create scan script
cat > scan_all.sh << 'EOF'
#!/bin/bash
for dir in project1 project2 project3; do
    echo "Scanning $dir..."
    python local_check.py -r $dir -o "${dir}_report.json"
done
EOF

chmod +x scan_all.sh
./scan_all.sh
```

### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install scanner
        run: |
          pip install requests
          cp patterns.env.example patterns.env
      
      - name: Run scan
        run: |
          python local_check.py -r . -o report.json
      
      - name: Check for high-confidence findings
        run: |
          python -c "
          import json
          with open('report.json') as f:
              data = json.load(f)
              high = [f for f in data['findings'] if f.get('score', 0) >= 5]
              if high:
                  print(f'❌ Found {len(high)} high-confidence secrets!')
                  exit(1)
              print('✓ No high-confidence secrets found')
          "
```

### Batch Scanning
```python
# batch_scan.py
from scanners import scan_files
import json

projects = [
    "/path/to/project1",
    "/path/to/project2",
    "/path/to/project3",
]

all_findings = []
for project in projects:
    print(f"Scanning {project}...")
    findings = scan_files(project)
    all_findings.extend(findings)

with open("batch_report.json", "w") as f:
    json.dump({"findings": all_findings}, f, indent=2)

print(f"Total findings: {len(all_findings)}")
```

## Next Steps

1. ✅ Run initial scan on your project
2. ✅ Review findings and rotate any real credentials
3. ✅ Add custom patterns for your company's API keys
4. ✅ Integrate into CI/CD pipeline
5. ✅ Set up pre-commit hooks
6. 🚀 Ready to build Chrome extension wrapper!
