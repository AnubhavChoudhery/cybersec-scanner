"""
Core utility functions for security analysis.

This module provides helper functions used across all scanners:
- Shannon entropy calculation for randomness detection
- Text file detection
- String literal extraction from source code
- Secret scoring and classification
"""
import math
import re
from config import (
    MIN_LEN, ENTROPY_THRESHOLD, SCORE_THRESHOLD,
    KNOWN_PATTERNS, STRING_LITERAL_RE, ASSIGN_CONTEXT_RE
)


def shannon_entropy(s: str):
    """
    Calculate Shannon entropy of a string to measure randomness/information density.
    
    Shannon entropy is a measure of unpredictability or information content.
    High entropy suggests random data (like API keys, tokens, hashes).
    Low entropy suggests structured/predictable data (like regular text).
    
    Args:
        s (str): Input string to analyze
        
    Returns:
        float: Entropy value in bits (0.0 = no entropy, ~8.0 = maximum for binary data)
        
    Example:
        shannon_entropy("aaaa") -> ~0.0 (very predictable)
        shannon_entropy("hello") -> ~2.3 (some variety)
        shannon_entropy("aK8$mX9#pQ2!") -> ~3.5+ (high randomness, likely a secret)
        
    Usage in security:
        Secrets/tokens typically have entropy > 3.5 due to random generation.
        Regular words/names have entropy < 3.0.
    """
    if not s:
        return 0.0
    
    # Count frequency of each character
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    
    # Calculate Shannon entropy: -Σ(p(x) * log2(p(x)))
    ent = 0.0
    L = len(s)
    for count in freq.values():
        p = count / L  # Probability of this character
        ent -= p * math.log2(p)
    
    return ent


def is_text_file(path: str):
    """
    Heuristic check to determine if a file is text-based or binary.
    
    Reads the first 4KB of the file and checks for null bytes.
    Presence of null bytes typically indicates binary content (images, executables, etc.).
    
    Args:
        path (str): Absolute file path to check
        
    Returns:
        bool: True if file appears to be text, False if binary or on error
        
    Notes:
        - This is a heuristic, not perfect (some binary formats may not have nulls in first 4KB)
        - Helps avoid wasting time parsing binary files like images, PDFs, executables
        - Returns False on any read error (permissions, missing file, etc.)
    """
    try:
        with open(path, "rb") as f:
            start = f.read(4096)
            # Binary files typically contain null bytes; text files don't
            if b"\x00" in start:
                return False
            return True
    except Exception:
        return False


def extract_string_literals(text: str):
    """
    Extract all string literals (quoted strings) from source code or text.
    
    Finds strings enclosed in single quotes ('), double quotes ("), or backticks (`).
    Also captures some surrounding context for better variable name analysis.
    
    Args:
        text (str): Source code or text content to parse
        
    Returns:
        list of tuples: Each tuple is (string_value, context)
            - string_value: The literal string content (without quotes)
            - context: ~160 chars of surrounding code for context analysis
            
    Filtering:
        - Ignores strings shorter than 8 characters (too short to be interesting)
        - Handles escaped quotes within strings
        
    Usage:
        Used to extract potential API keys, tokens, passwords that developers
        often hardcode as string literals in their source code.
        
    Example:
        Input: 'const apiKey = "sk_live_abc123def456";'
        Output: [("sk_live_abc123def456", "const apiKey = ...")]
    """
    out = []
    for m in STRING_LITERAL_RE.finditer(text):
        s = m.group("s")  # The string content (without quotes)
        
        # Skip very short strings - they're rarely secrets
        if len(s) < 8:
            continue
        
        # Grab surrounding context (~80 chars before and after)
        start, end = m.span()
        ctx = text[max(0, start - 80):min(len(text), end + 80)]
        
        out.append((s, ctx))
    return out


def score_literal(s: str, context: str = ""):
    """
    Score a string literal's likelihood of being a secret/credential.
    
    Uses multiple heuristics to assess if a string might be an API key, token,
    password, or other sensitive credential. Higher scores indicate higher confidence.
    
    Args:
        s (str): The string literal to analyze
        context (str): Surrounding code context (helps detect variable names)
        
    Returns:
        tuple: (score, reasons, entropy)
            - score (int): Confidence score (0-10+, threshold is typically 2-3)
            - reasons (list of str): Human-readable explanations for the score
            - entropy (float): Shannon entropy value (randomness measure)
            
    Scoring Criteria:
        +1 point: Length >= MIN_LEN (20 chars)
        +1 point: Entropy >= ENTROPY_THRESHOLD (3.5)
        +3 points: Matches known pattern (AWS key, Stripe, etc.) - STRONGEST signal
        +1 point: Looks like base64 encoding
        +1 point: Looks like hex encoding
        +1 point: Long alphanumeric string
        +2 points: Variable name contains keywords like "key", "token", "secret", "api"
        
    Example:
        score_literal("sk_live_abc123...", "const stripeKey = ...")
        -> (6, ["len=20", "entropy=3.8", "pattern=Stripe Secret", "varname_hint"], 3.8)
    """
    reasons = []
    score = 0
    L = len(s)
    ent = shannon_entropy(s)
    
    # Length check: longer strings more likely to be tokens
    if L >= MIN_LEN:
        score += 1
        reasons.append(f"len={L}")
    
    # Entropy check: high randomness suggests generated secrets
    if ent >= ENTROPY_THRESHOLD:
        score += 1
        reasons.append(f"entropy={ent:.2f}")
    
    # Known pattern check: STRONGEST indicator - exact format match
    for name, pat in KNOWN_PATTERNS.items():
        if pat.search(s):
            score += 3
            reasons.append(f"pattern={name}")
            break  # Only count first pattern match
    
    # Base64-like: typically used for encoding tokens/keys
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", s):
        score += 1
        reasons.append("base64_like")
    
    # Hex-like: common for hashes and some API keys
    if re.fullmatch(r"[0-9a-fA-F]{20,}", s):
        score += 1
        reasons.append("hex_like")
    
    # Long alphanumeric: generic pattern for many tokens
    if re.fullmatch(r"[A-Za-z0-9\-_]{20,}", s):
        score += 1
        reasons.append("alphanum_like")
    
    # Context analysis: check if variable name suggests a secret
    m = ASSIGN_CONTEXT_RE.search(context)
    if m:
        # Extract variable name from context
        candidate = "".join([g for g in m.groups() if g])
        # Check for security-relevant keywords in variable name
        if re.search(r"key|token|secret|api|auth|cred|pass", candidate, re.I):
            score += 2
            reasons.append("varname_hint")
    
    return score, reasons, ent
