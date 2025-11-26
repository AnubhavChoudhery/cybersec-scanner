"""
Test the public API to ensure clean imports and usage.
"""

def test_imports():
    """Test that all public APIs can be imported."""
    print("Testing imports...")
    
    try:
        from cybersec_scanner import (
            __version__,
            GitScanner,
            WebCrawler,
            NetworkScanner,
            KnowledgeGraph,
            Retriever,
            OllamaClient,
            DatabaseNormalizer,
            scan,
            query,
        )
        print(f"✅ All imports successful (v{__version__})")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_exception_hierarchy():
    """Test custom exceptions."""
    print("\nTesting exception hierarchy...")
    
    try:
        from cybersec_scanner import (
            CyberSecScannerError,
            ScannerError,
            GraphError,
            ValidationError,
        )
        
        # Test inheritance
        assert issubclass(ScannerError, CyberSecScannerError)
        assert issubclass(GraphError, CyberSecScannerError)
        assert issubclass(ValidationError, CyberSecScannerError)
        
        print("✅ Exception hierarchy correct")
        return True
    except Exception as e:
        print(f"❌ Exception test failed: {e}")
        return False


def test_convenience_functions():
    """Test convenience wrapper functions."""
    print("\nTesting convenience functions...")
    
    try:
        # Just check they're callable
        from cybersec_scanner import scan, query
        
        assert callable(scan)
        assert callable(query)
        
        print("✅ Convenience functions available")
        return True
    except Exception as e:
        print(f"❌ Convenience function test failed: {e}")
        return False


def main():
    print("="*60)
    print("🧪 PUBLIC API TEST")
    print("="*60)
    
    results = [
        test_imports(),
        test_exception_hierarchy(),
        test_convenience_functions(),
    ]
    
    print("\n" + "="*60)
    if all(results):
        print("🎉 Public API is working correctly!")
    else:
        print("⚠️  Some API tests failed")
    print("="*60)


if __name__ == "__main__":
    main()
