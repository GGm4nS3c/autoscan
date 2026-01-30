"""
Autoscan package.

Provides a CLI-driven network scanning workflow built on top of Nmap,
with resume-aware orchestration, SQLite persistence and reporting
capabilities.
"""

__version__ = "1.0.0"

from .cli import main  # noqa: E402

__all__ = ["main", "__version__"]
