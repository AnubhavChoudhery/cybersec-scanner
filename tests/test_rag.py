#!/usr/bin/env python
"""
Quick test script to verify RAG components work.
"""

def test_normalizer():
    """Test database normalizer."""
    print("=" * 60)
    print("Testing Database Normalizer...")
    print("=" * 60)
    
    try:
        from database.normalizer import normalize_graph_to_db
        stats = normalize_graph_to_db('rag/graph.gpickle')
        print(f"[OK] Normalizer works!")
        print(f"   Stats: {stats}")
        return True
    except Exception as e:
        print(f"[FAIL] Normalizer failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_query_db():
    """Test querying the database."""
    print("\n" + "=" * 60)
    print("Testing Database Queries...")
    print("=" * 60)
    
    try:
        from database.normalizer import DatabaseNormalizer
        normalizer = DatabaseNormalizer()
        
        # Get stats
        stats = normalizer.get_stats()
        print(f"[OK] Database query works!")
        print(f"   Database stats: {stats}")
        
        # Query critical findings
        if stats["findings"] > 0:
            critical = normalizer.query_findings(severity="CRITICAL", limit=3)
            print(f"\n   Critical findings ({len(critical)}):")
            for f in critical[:3]:
                print(f"     - {f['summary']} [{f['severity']}]")
        
        return True
    except Exception as e:
        print(f"[FAIL] Database query failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_retriever():
    """Test retriever."""
    print("\n" + "=" * 60)
    print("Testing Retriever...")
    print("=" * 60)
    
    try:
        from pathlib import Path
        from rag.retriever import Retriever
        
        retriever = Retriever(graph_path=Path("rag/graph.gpickle"))
        results = retriever.retrieve("API key", k=3, mode="graph")
        
        print(f"[OK] Retriever works!")
        print(f"   Found {len(results)} results for 'API key'")
        for r in results[:3]:
            print(f"     - {r.get('summary', 'N/A')} [{r.get('severity', 'N/A')}]")
        
        return True
    except Exception as e:
        print(f"[FAIL] Retriever failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli():
    """Test CLI."""
    print("\n" + "=" * 60)
    print("Testing CLI Query...")
    print("=" * 60)
    
    try:
        from rag.cli import query_graph_and_llm
        
        print("   Note: This will call Ollama, make sure it's running!")
        result = query_graph_and_llm(
            query="How do I fix API key exposure?",
            graph_path="rag/graph.gpickle",
            model="gemma3:1b"
        )
        
        print(f"[OK] CLI works!")
        print(f"   Retrieved {len(result.get('contexts', []))} contexts")
        print(f"   LLM response length: {len(result.get('answer', ''))} chars")
        
        return True
    except Exception as e:
        print(f"[FAIL] CLI failed (this is OK if Ollama not running): {e}")
        return False


if __name__ == "__main__":
    print("\n🧪 Running RAG Component Tests\n")
    
    results = []
    results.append(("Normalizer", test_normalizer()))
    results.append(("Database Query", test_query_db()))
    results.append(("Retriever", test_retriever()))
    results.append(("CLI (optional)", test_cli()))
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} - {name}")
    
    passed_count = sum(1 for _, p in results if p)
    total = len(results)
    
    print(f"\nPassed: {passed_count}/{total}")
    
    if passed_count == total:
        print("\n🎉 All tests passed!")
    elif passed_count >= total - 1:  # Allow CLI to fail if Ollama not running
        print("\n[OK] Core components working!")
    else:
        print("\n⚠️ Some tests failed - check errors above")
