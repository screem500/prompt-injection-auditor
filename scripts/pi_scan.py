#!/usr/bin/env python3
"""Compatibility wrapper for legacy scripts/pi_scan.py usage."""
from pi_auditor.scanner import *  # noqa: F401,F403
from pi_auditor.scanner import main

if __name__ == "__main__":
    main()
