"""
Core utility functions for security analysis.

Text file detection for scanner filtering.
"""


def is_text_file(path: str):
    """
    Check if a file is text-based or binary.
    
    Reads first 4KB and checks for null bytes.
    
    Args:
        path: Absolute file path to check
        
    Returns:
        bool: True if text, False if binary or error
    """
    try:
        with open(path, "rb") as f:
            start = f.read(4096)
            if b"\x00" in start:
                return False
            return True
    except Exception:
        return False
