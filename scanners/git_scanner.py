"""
Git history scanner for detecting secrets in version control history.

Uses efficient pickaxe search with pattern matching to find committed secrets.
"""
import os
import subprocess
import re
from config import KNOWN_PATTERNS


def scan_git_history(root, max_commits=100):
    """
    Scan git history for secrets using pattern-based pickaxe search.
    
    Args:
        root: Absolute path to git repository root
        max_commits: Maximum total commits to examine across all patterns (default: 100)
        
    Returns:
        List of findings with: type, commit, path, pattern, snippet
    """
    results = []
    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        return results
    
    # Build search terms from KNOWN_PATTERNS - extract known prefixes/markers
    search_terms = {}
    
    # Extract search strings from patterns
    for name, pattern in KNOWN_PATTERNS.items():
        pattern_str = pattern.pattern
        
        # Extract known prefixes that appear at start of pattern
        if pattern_str.startswith('AKIA'):
            search_terms['AKIA'] = name
        elif pattern_str.startswith('AIza'):
            search_terms['AIza'] = name
        elif pattern_str.startswith('sk-'):
            search_terms['sk-'] = name
        elif pattern_str.startswith('sk_live_'):
            search_terms['sk_live_'] = name
        elif pattern_str.startswith('sk_test_'):
            search_terms['sk_test_'] = name
        elif pattern_str.startswith('gsk_'):
            search_terms['gsk_'] = name
        elif pattern_str.startswith('hf_'):
            search_terms['hf_'] = name
        elif pattern_str.startswith('r8_'):
            search_terms['r8_'] = name
        elif pattern_str.startswith('xox'):
            search_terms['xox'] = name
        elif pattern_str.startswith('ghp_'):
            search_terms['ghp_'] = name
        elif pattern_str.startswith('gho_'):
            search_terms['gho_'] = name
        elif pattern_str.startswith('glpat-'):
            search_terms['glpat-'] = name
        elif pattern_str.startswith('AC['):
            search_terms['AC'] = name
        elif pattern_str.startswith('SK['):
            search_terms['SK'] = name
        elif pattern_str.startswith('SG'):
            search_terms['SG.'] = name
        elif pattern_str.startswith('key-'):
            search_terms['key-'] = name
        elif pattern_str.startswith('sq0'):
            search_terms['sq0'] = name
        elif pattern_str.startswith('shpat_'):
            search_terms['shpat_'] = name
        elif pattern_str.startswith('eyJ'):
            search_terms['eyJ'] = name
        elif pattern_str.startswith('mongodb'):
            search_terms['mongodb'] = name
        elif pattern_str.startswith('postgres'):
            search_terms['postgres'] = name
        elif pattern_str.startswith('mysql'):
            search_terms['mysql'] = name
        elif pattern_str.startswith('redis'):
            search_terms['redis'] = name
        elif pattern_str.startswith('https://[a-f0-9]{32}'):
            search_terms['sentry'] = name
        elif pattern_str.startswith('[A-Za-z0-9_-]{24}'):
            search_terms['Discord'] = name
        elif pattern_str.startswith('[0-9]{8,10}:'):
            search_terms['Telegram'] = name
        elif pattern_str.startswith('AAAA'):
            search_terms['AAAA'] = name
        elif pattern_str.startswith('EAA'):
            search_terms['EAA'] = name
        elif pattern_str.startswith('secret_'):
            search_terms['secret_'] = name
        elif pattern_str.startswith('ntn_'):
            search_terms['ntn_'] = name
        elif pattern_str.startswith('key['):
            search_terms['key'] = name
        elif pattern_str.startswith('pk'):
            search_terms['pk.'] = name
        elif pattern_str.startswith('pypi-'):
            search_terms['pypi-'] = name
        elif '-----BEGIN' in pattern_str:
            search_terms['-----BEGIN'] = name
        elif 'bearer' in pattern_str.lower():
            search_terms['bearer'] = name
        elif 'ya29' in pattern_str:
            search_terms['ya29'] = name
    
    # If no search terms extracted, fall back to scanning all patterns
    if not search_terms:
        print("  [git] Warning: No search terms extracted from patterns")
        return results
    
    try:
        commit_count_raw = subprocess.check_output(
            ["git", "-C", root, "rev-list", "--all", "--count"],
            text=True,
            encoding='utf-8',
            errors='ignore',
            stderr=subprocess.DEVNULL
        )
        total_commits = int(commit_count_raw.strip())
        print(f"  [git] Repository has {total_commits} commits, scanning up to {max_commits} most recent...")
    except Exception:
        print(f"  [git] Scanning up to {max_commits} commits...")
    
    commits_examined = 0
    max_per_term = max(1, max_commits // len(search_terms))
    
    # For each search term, use pickaxe to find relevant commits
    for search_str, pattern_name in search_terms.items():
        if commits_examined >= max_commits:
            break
            
        try:
            result = subprocess.check_output(
                ["git", "-C", root, "log", "--all", "--format=%H", f"-S{search_str}", 
                 "-n", str(max_per_term)],
                text=True,
                encoding='utf-8',
                errors='ignore',
                stderr=subprocess.DEVNULL
            )
            
            commits_with_term = result.strip().splitlines()
            if not commits_with_term:
                continue
                
            # Process commits for this search term
            for commit in commits_with_term:
                if commits_examined >= max_commits:
                    break
                    
                commits_examined += 1
                
                try:
                    diff_output = subprocess.check_output(
                        ["git", "-C", root, "show", commit],
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        stderr=subprocess.DEVNULL
                    )
                    
                    # Get file path from diff
                    file_match = re.search(r'\+\+\+ b/(.+)', diff_output)
                    file_path = file_match.group(1) if file_match else "unknown"
                    
                    # Scan entire diff with ALL patterns (not just the search term's pattern)
                    for name, pat in KNOWN_PATTERNS.items():
                        for line in diff_output.splitlines():
                            # Only look at added lines (starting with +)
                            if line.startswith('+') and not line.startswith('+++'):
                                match = pat.search(line)
                                if match:
                                    # Avoid duplicates
                                    snippet = match.group(0)[:200]
                                    finding = {
                                        "type": "git_pattern",
                                        "commit": commit[:12],
                                        "path": file_path,
                                        "pattern": name,
                                        "snippet": snippet
                                    }
                                    # Check if this exact finding already exists
                                    if not any(
                                        r["commit"] == finding["commit"] and 
                                        r["snippet"] == finding["snippet"]
                                        for r in results
                                    ):
                                        results.append(finding)
                            
                except Exception:
                    continue
                    
        except Exception:
            continue
    
    print(f"  [git] Examined {commits_examined} commits, found {len(results)} secrets")
    return results
