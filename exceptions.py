"""
Custom exceptions for the CyberSec Scanner library.
"""


class CyberSecScannerError(Exception):
    """Base exception for all library errors."""
    pass


class ScannerError(CyberSecScannerError):
    """Raised when a scanner module fails."""
    pass


class GraphError(CyberSecScannerError):
    """Raised when knowledge graph operations fail."""
    pass


class DatabaseError(CyberSecScannerError):
    """Raised when database operations fail."""
    pass


class RetrieverError(CyberSecScannerError):
    """Raised when retrieval operations fail."""
    pass


class EmbeddingError(CyberSecScannerError):
    """Raised when embedding generation fails."""
    pass


class LLMError(CyberSecScannerError):
    """Raised when LLM client operations fail."""
    pass


class ConfigurationError(CyberSecScannerError):
    """Raised when configuration is invalid."""
    pass


class ValidationError(CyberSecScannerError):
    """Raised when input validation fails."""
    pass
