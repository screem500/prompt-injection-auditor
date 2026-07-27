#!/usr/bin/env python3
"""Compatibility wrapper for legacy scripts/pi_shield.py usage."""
from pi_auditor.shield import *  # noqa: F401,F403
from pi_auditor.shield import _main

if __name__ == "__main__":
    _main()
