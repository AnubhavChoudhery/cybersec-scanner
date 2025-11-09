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
    
    # Build search terms from known patterns
    search_terms = {
        "AKIA": "AWS Access Key",
        "AIza": "Google API Key",
        "sk_live_": "Stripe Secret",
        "sk_test_": "Stripe Test Key",
        "xox": "Slack Token",
        "-----BEGIN": "Private Key",
        "bearer": "Bearer Token",
    }
    
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
                    
                    # Parse diff and validate with actual patterns
                    for line in diff_output.splitlines():
                        if search_str.lower() in line.lower():
                            # Verify with regex patterns
                            for name, pat in KNOWN_PATTERNS.items():
                                match = pat.search(line)
                                if match:
                                    file_match = re.search(r'\+\+\+ b/(.+)', diff_output)
                                    file_path = file_match.group(1) if file_match else "unknown"
                                    
                                    results.append({
                                        "type": "git_pattern",
                                        "commit": commit[:12],
                                        "path": file_path,
                                        "pattern": name,
                                        "snippet": match.group(0)[:200]
                                    })
                                    break
                            
                except Exception:
                    continue
                    
        except Exception:
            continue
    
    print(f"  [git] Examined {commits_examined} commits, found {len(results)} secrets")
    return results
