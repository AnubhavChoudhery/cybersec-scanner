"""
Configuration constants and patterns for the security audit tool.

Pattern-based secret detection using regex patterns from patterns.env.
"""
import re
import os
from pathlib import Path

# -------- FILE SCANNING CONFIGURATION --------

# File extensions to exclude from static analysis (binary/non-text files)
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
KNOWN_PATTERNS = load_patterns_from_env()

# Regex patterns for parsing and extracting information

# SOURCE_MAP_RE: Finds source map references in JavaScript files
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*(?P<url>[\w\-\_\.\/\\]+\.map)")

# JS_URL_RE: Extracts URLs from HTML src/href attributes
JS_URL_RE = re.compile(r'(?:src|href)=["\']([^"\']+)["\']', re.I)
