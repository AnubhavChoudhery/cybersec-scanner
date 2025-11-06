"""
Git history scanner for detecting secrets in version control history.

This module analyzes git commit history to find secrets that may have been
committed and later removed. Uses efficient pickaxe search to avoid
scanning every commit individually.
"""
import os
import subprocess
import re
from config import KNOWN_PATTERNS


def scan_git_history(root):
    """
    Scan git commit history for potential secrets using pattern-based detection.
    
    This function uses git log with pickaxe search (-S) to efficiently find commits
    that introduced specific strings matching known secret patterns. This is much
    faster than grepping through every commit individually.
    
    Args:
        root (str): Absolute path to the git repository root
        
    Returns:
        list: List of findings, each a dict with type, commit, path, pattern, and snippet
        
    Performance Notes:
        - Uses git log -S (pickaxe) instead of git grep for better performance
        - Searches for specific pattern components (e.g., "AKIA" for AWS keys)
        - Only examines commits that actually modified lines containing the search term
        
    Security Notes:
        - Uses subprocess with list arguments (not shell=True) to prevent injection
        - Limits search terms to prevent excessive runtime on large repos
    """
    results = []
    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        return results
    
    # Build search terms from known patterns - extract distinctive literal strings
    # These are the "smoking gun" prefixes/patterns that identify specific secret types
    search_terms = {
        "AKIA": "AWS Access Key",  # AWS access keys always start with AKIA
        "AIza": "Google API Key",   # Google API keys start with AIza
        "sk_live_": "Stripe Secret (sk_live_)",
        "sk_test_": "Stripe Test Key (sk_test_)",
        "xox": "Slack Token",  # Slack tokens start with xox[baprs]
        "-----BEGIN": "Possible Private Key BEGIN",
        "HEROKU_API_KEY": "Heroku API Key",
        "bearer": "OAuth Bearer token",
    }
    
    try:
        # Get total commit count for progress indication
        commit_count_raw = subprocess.check_output(
            ["git", "-C", root, "rev-list", "--all", "--count"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        total_commits = int(commit_count_raw.strip())
        print(f"  [git] Scanning {total_commits} commits for secrets...")
    except Exception:
        total_commits = 0
        print("  [git] Commit count unavailable, proceeding with scan...")
    
    # For each search term, use git log pickaxe (-S) to find commits that added/removed it
    for search_str, pattern_name in search_terms.items():
        try:
            # Use git log -S (pickaxe) to find commits that changed occurrences of search_str
            # --all: search all branches
            # --format=%H: output only commit hash
            # -S: pickaxe search (finds commits that change the number of occurrences)
            # No shell=True - safe from injection
            result = subprocess.check_output(
                ["git", "-C", root, "log", "--all", "--format=%H", f"-S{search_str}"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=30  # Timeout per search term to prevent hanging
            )
            
            commits_with_term = result.strip().splitlines()
            if not commits_with_term:
                continue
                
            # For each commit found, get the actual changes to verify pattern match
            for commit in commits_with_term[:20]:  # Limit to first 20 commits per pattern
                try:
                    # Get diff for this commit, searching for our term
                    diff_output = subprocess.check_output(
                        ["git", "-C", root, "show", commit],
                        text=True,
                        stderr=subprocess.DEVNULL,
                        timeout=10
                    )
                    
                    # Parse diff to find relevant lines and validate with actual patterns
                    for line in diff_output.splitlines():
                        # Look for added lines (starting with +) containing our search term
                        if search_str.lower() in line.lower():
                            # Verify against actual regex patterns for this finding
                            for name, pat in KNOWN_PATTERNS.items():
                                if pat.search(line):
                                    # Extract file path from diff if available
                                    file_match = re.search(r'\+\+\+ b/(.+)', diff_output)
                                    file_path = file_match.group(1) if file_match else "unknown"
                                    
                                    results.append({
                                        "type": "git_match",
                                        "commit": commit[:12],  # Short hash for readability
                                        "path": file_path,
                                        "pattern": name,
                                        "snippet": line.strip()[:200]  # Truncate long lines
                                    })
                                    break  # One match per line is enough
                            
                except subprocess.TimeoutExpired:
                    print(f"  [git] Timeout examining commit {commit[:8]}, skipping...")
                    continue
                except Exception:
                    continue
                    
        except subprocess.TimeoutExpired:
            print(f"  [git] Timeout searching for '{search_str}', skipping...")
            continue
        except Exception as e:
            # Silently continue on errors (repo might not have history for this term)
            continue
    
    print(f"  [git] Found {len(results)} potential secrets in git history")
    return results
