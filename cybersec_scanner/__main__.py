#!/usr/bin/env python3
"""
Entry point script for cybersec-scanner CLI.
Can be used directly: python -m cybersec_scanner.cli
"""

if __name__ == "__main__":
    from cybersec_scanner.cli.main import main
    import sys
    sys.exit(main())
