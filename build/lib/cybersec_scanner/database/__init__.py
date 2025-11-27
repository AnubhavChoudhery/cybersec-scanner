"""
Database normalization and storage for vulnerability findings.

This module provides SQLite-based persistence for:
- Findings storage and querying
- CWE/OWASP mappings
- Relationship tracking
"""

from .normalizer import DatabaseNormalizer, normalize_graph_to_db

__all__ = [
    "DatabaseNormalizer",
    "normalize_graph_to_db",
]
