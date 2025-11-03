"""
Autoscan package.

Provides a CLI-driven network scanning workflow built on top of Nmap,
with resume-aware orchestration, SQLite persistence and reporting
capabilities.
"""

from .cli import main

__all__ = ["main"]

