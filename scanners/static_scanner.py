"""
Static file scanner for detecting hardcoded secrets in source code.

This module recursively scans directories for text files and analyzes them
for potential secrets, API keys, tokens, and credentials using:
- String literal extraction
- Entropy analysis
- Pattern matching
- Context-aware scoring
"""
import os
from config import EXCLUDE_SUFFIXES, KNOWN_PATTERNS, SCORE_THRESHOLD
from utils import is_text_file, extract_string_literals, score_literal


def scan_files(root):
    """
    Recursively scan all text files in a directory for potential secrets.
    
    Walks through the directory tree, analyzes text files, and identifies
    potential API keys, tokens, passwords, and other credentials using:
    1. String literal extraction and scoring
    2. Pattern matching against known secret formats
    
    Args:
        root (str): Absolute path to root directory to scan
        
    Returns:
        list: List of finding dictionaries, each containing:
            - type: "static_literal" or "static_known"
            - file: File path where secret was found
            - snippet: The suspicious string (truncated to 300 chars)
            - score: Confidence score (for literals)
            - reasons: List of reasons for detection (for literals)
            - pattern: Pattern name (for known patterns)
            
    Exclusions:
        - Binary file types (images, archives, executables)
        - Symbolic links (to avoid infinite loops)
        - Files that fail text detection
        
    Performance:
        Processes files sequentially. For large codebases (>10k files),
        this may take several minutes. Consider adding progress indicators
        for production use.
    """
    findings = []
    
    for dirpath, dirs, files in os.walk(root):
        for fn in files:
            # Skip binary files by extension
            if fn.lower().endswith(tuple(EXCLUDE_SUFFIXES)):
                continue
            
            full = os.path.join(dirpath, fn)
            
            # Skip symbolic links to avoid infinite loops
            if os.path.islink(full):
                continue
            
            # Skip binary files by content inspection
            if not is_text_file(full):
                continue
            
            # Read file content
            try:
                txt = open(full, "r", errors="ignore").read()
            except Exception:
                continue
            
            # ANALYSIS 1: Extract and score string literals
            for s, ctx in extract_string_literals(txt):
                score, reasons, ent = score_literal(s, ctx)
                
                # Only report if score meets threshold
                if score >= SCORE_THRESHOLD:
                    findings.append({
                        "type": "static_literal",
                        "file": full,
                        "snippet": s[:300],  # Truncate long strings
                        "score": score,
                        "reasons": reasons,
                        "entropy": ent
                    })
            
            # ANALYSIS 2: Direct pattern matching for known secret formats
            for name, pat in KNOWN_PATTERNS.items():
                if pat.search(txt):
                    findings.append({
                        "type": "static_known",
                        "file": full,
                        "pattern": name
                    })
    
    return findings
