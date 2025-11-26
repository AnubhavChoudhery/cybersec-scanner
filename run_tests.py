#!/usr/bin/env python3
"""
Consolidated test runner with smart mode selection.

Usage:
    python run_tests.py                # Run all tests (skip LLM if Ollama unavailable)
    python run_tests.py --all          # Run all tests including LLM
    python run_tests.py --fast         # Run only unit tests (no LLM)
    python run_tests.py --coverage     # Run with coverage report
    python run_tests.py --file retriever  # Run specific test file
"""

import sys
import subprocess
import requests
from pathlib import Path


def is_ollama_available():
    """Check if Ollama service is running."""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


def run_command(cmd, description):
    """Run command and print status."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}\n")
    
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    
    if result.returncode == 0:
        print(f"\n✅ {description} PASSED\n")
    else:
        print(f"\n❌ {description} FAILED\n")
    
    return result.returncode


def main():
    args = sys.argv[1:]
    
    # Check Ollama availability
    ollama_available = is_ollama_available()
    
    if ollama_available:
        print("✅ Ollama detected - LLM tests will run")
    else:
        print("⚠️  Ollama not detected - LLM tests will be skipped")
        print("   Start Ollama with: ollama serve")
        print("   Or install from: https://ollama.com\n")
    
    # Determine test mode
    if "--all" in args:
        # Force all tests including LLM (will fail if Ollama unavailable)
        cmd = ["pytest", "tests/", "-v"]
        description = "All tests (including LLM)"
    
    elif "--fast" in args:
        # Unit tests only
        cmd = ["pytest", "tests/", "-v", "-k", "not llm_client"]
        description = "Fast unit tests (no LLM)"
    
    elif "--coverage" in args:
        # Coverage report
        skip_llm = [] if ollama_available else ["-k", "not llm_client"]
        cmd = ["pytest", "tests/", "-v", "--cov=rag", "--cov=database", "--cov-report=term-missing"] + skip_llm
        description = "All tests with coverage"
    
    elif "--file" in args:
        # Specific file
        try:
            idx = args.index("--file")
            filename = args[idx + 1]
            test_file = f"tests/test_{filename}.py"
            if not Path(test_file).exists():
                print(f"❌ Test file not found: {test_file}")
                print(f"   Available: knowledge_graph, cwe_enrichment, normalizer, retriever, llm_client, end_to_end")
                return 1
            cmd = ["pytest", test_file, "-v"]
            description = f"Test file: {filename}"
        except (IndexError, ValueError):
            print("❌ Usage: python run_tests.py --file <filename>")
            print("   Example: python run_tests.py --file retriever")
            return 1
    
    elif "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    
    else:
        # Default: run all but skip LLM if unavailable
        if ollama_available:
            cmd = ["pytest", "tests/", "-v"]
            description = "All tests"
        else:
            cmd = ["pytest", "tests/", "-v", "-k", "not llm_client"]
            description = "All tests (LLM tests skipped - Ollama unavailable)"
    
    # Run tests
    return run_command(cmd, description)


if __name__ == "__main__":
    sys.exit(main())
