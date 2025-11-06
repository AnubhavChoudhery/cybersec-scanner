"""
Configuration constants and patterns for the security audit tool.

This module contains all configurable parameters, regex patterns,
and constants used throughout the security scanning process.

Patterns are loaded from patterns.env to avoid exposing sensitive
regex signatures in version control.
"""
import re
import os
from pathlib import Path

# -------- SCORING CONFIGURATION --------
# These constants control the sensitivity and behavior of the security scanner.
# Adjust these values to tune false positive rates vs. detection sensitivity.

# Minimum string length (in characters) to be considered as a potential secret
# Shorter strings are less likely to be meaningful secrets
# Default: 20 characters (catches most API keys, tokens, passwords)
MIN_LEN = 20

# Minimum Shannon entropy threshold for flagging high-randomness strings
# Shannon entropy measures unpredictability (0 = all same char, ~8 = maximum randomness)
# Secrets typically have high entropy due to random generation
# Default: 3.5 bits (good balance - regular text ~2.5, random tokens ~4.0+)
ENTROPY_THRESHOLD = 3.5

# Minimum score threshold for reporting a finding
# Score is cumulative from multiple heuristics (length, entropy, patterns, context)
# Lower = more findings but more false positives; Higher = fewer false positives but may miss secrets
# Default: 2 points (catches most secrets with reasonable FP rate)
SCORE_THRESHOLD = 2

# -------- FILE SCANNING CONFIGURATION --------

# File extensions to exclude from static analysis (binary/non-text files)
# Scanning these would waste time and produce garbage results
EXCLUDE_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif',  # Images
    '.zip', '.tar', '.gz',            # Archives
    '.db', '.sqlite',                 # Databases
    '.wasm', '.dll', '.exe'          # Executables/binaries
}

# -------- WEB CRAWLER CONFIGURATION --------

# Common paths that often contain secrets or sensitive configuration
# These are probed directly during the HTTP crawl phase
# Add more paths specific to your tech stack (e.g., '/wp-config.php' for WordPress)
PROBE_PATHS = [
    # Environment files (common in Node.js, Python, Ruby apps)
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    
    # Git metadata (often accidentally exposed on production servers)
    "/.git/config", "/.git/HEAD", "/.git/index",
    
    # Configuration files and backups
    "/config.php", "/config.php.bak", "/config.yml", "/database.yml",
    
    # Server information disclosure
    "/phpinfo.php", "/server-status", "/info.php",
    
    # Authentication and access control
    "/.htpasswd", "/.htaccess",
    
    # Development artifacts
    "/.DS_Store", "/.gitignore", 
    
    # CI/CD configuration (may contain deployment keys)
    "/.circleci/config.yml", "/.travis.yml", "/.github/workflows",
]

# -------- PATTERN DEFINITIONS --------

def load_patterns_from_env():
    """
    Load secret detection patterns from patterns.env file.
    
    This keeps sensitive regex patterns out of version control.
    Falls back to basic patterns if patterns.env is not found.
    
    Returns:
        dict: Dictionary mapping pattern names to compiled regex objects
    """
    patterns = {}
    env_file = Path(__file__).parent / "patterns.env"
    
    if not env_file.exists():
        print(f"[WARNING] {env_file} not found. Using minimal fallback patterns.")
        print("          Create patterns.env from patterns.env.example for full coverage.")
        # Fallback to minimal patterns
        return {
            "Generic API Key": re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}"),
            "Generic Secret": re.compile(r"(?i)secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}"),
            "Private Key": re.compile(r"-----BEGIN (RSA|PRIVATE|OPENSSH|EC) (PRIVATE )?KEY-----"),
        }
    
    try:
        with open(env_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE format
                if '=' in line:
                    key, pattern_str = line.split('=', 1)
                    key = key.strip()
                    pattern_str = pattern_str.strip()
                    
                    if not pattern_str:
                        continue
                    
                    try:
                        # Compile regex pattern with case-insensitive flag if needed
                        # Some patterns have (?i) inline, but we compile all with re.I for consistency
                        compiled = re.compile(pattern_str)
                        
                        # Convert snake_case to Title Case for display
                        display_name = key.replace('_', ' ').title()
                        patterns[display_name] = compiled
                        
                    except re.error as e:
                        print(f"[WARNING] Invalid regex on line {line_num} in patterns.env: {e}")
                        continue
        
        print(f"[OK] Loaded {len(patterns)} secret detection patterns from patterns.env")
        
    except Exception as e:
        print(f"[WARNING] Error loading patterns.env: {e}")
        print("          Using minimal fallback patterns.")
        return {
            "Generic API Key": re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}"),
            "Generic Secret": re.compile(r"(?i)secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}"),
            "Private Key": re.compile(r"-----BEGIN (RSA|PRIVATE|OPENSSH|EC) (PRIVATE )?KEY-----"),
        }
    
    return patterns


# Load patterns dynamically from patterns.env
# This keeps sensitive regex signatures out of the codebase
KNOWN_PATTERNS = load_patterns_from_env()

# Regex patterns for parsing code and extracting security-relevant information

# STRING_LITERAL_RE: Matches quoted string literals in source code
# Supports single quotes ('), double quotes ("), and backticks (`)
# Handles escaped quotes within strings (e.g., "He said \"hello\"")
# Named groups: q = quote character, s = string content
STRING_LITERAL_RE = re.compile(r"""(?P<q>['"`])(?P<s>(?:\\.|(?!\1).)*)\1""", re.S)

# ASSIGN_CONTEXT_RE: Detects variable assignments that might contain secrets
# Matches patterns like:
#   const apiKey = "..."
#   let token = "..."
#   var password = "..."
#   apiKey: "..."  (object properties)
#   window.API_KEY = "..."  (global assignments)
# Captures the variable name for keyword analysis (key, token, secret, etc.)
ASSIGN_CONTEXT_RE = re.compile(
    r"""(?:(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*|([A-Za-z0-9_$]+)\s*:\s*|window\.([A-Za-z0-9_$]+)\s*=\s*)['"`]""",
    re.I
)

# SOURCE_MAP_RE: Finds source map references in JavaScript files
# Source maps may contain original source code with unminified secrets
# Matches: //# sourceMappingURL=app.js.map or //@ sourceMappingURL=...
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*(?P<url>[\w\-\_\.\/\\]+\.map)")

# JS_URL_RE: Extracts URLs from HTML src/href attributes
# Used by crawler to discover JavaScript files and linked pages
# Matches: src="..." or href="..."
JS_URL_RE = re.compile(r'(?:src|href)=["\']([^"\']+)["\']', re.I)
