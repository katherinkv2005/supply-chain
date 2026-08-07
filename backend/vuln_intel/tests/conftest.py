"""
conftest.py
-----------
Pytest configuration for vuln_intel tests.

Adds `src/` to sys.path so pytest can find `vulnerability_parser`
and `grype_scanner` without needing a package install.
This replaces the manual sys.path.insert() hack in each test file.
"""
import sys
from pathlib import Path

# Insert src/ at the front of sys.path once for the whole test session
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
