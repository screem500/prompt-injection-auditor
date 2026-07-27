#!/usr/bin/env python3
"""Compatibility wrapper for legacy scripts/mcp_guard.py usage."""
from pi_auditor.mcp_guard import *  # noqa: F401,F403
from pi_auditor.mcp_guard import _main

if __name__ == "__main__":
    _main()
