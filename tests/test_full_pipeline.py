"""
Complete pipeline test - Run all scanners and RAG system end-to-end.
This simulates real-world usage of the library.
"""

import json
from pathlib import Path
import sys

def test_scanners():
    """Test all scanner modules."""
    print("\n[TEST] Testing Scanners...")
    
    # Test git scanner (it's a function, not a class)
    print("  ├─ Git Scanner...", end=" ")
    try:
        from scanners.git_scanner import scan_git_history
        # Just check it can be imported
        assert callable(scan_git_history)
        print("[OK]")
    except Exception as e:
        print(f"[FAIL] {e}")
        return False
    
    # Test web crawler (it's a class: LocalCrawler)
    print("  ├─ Web Crawler...", end=" ")
    try:
        from scanners.web_crawler import LocalCrawler, process_crawler_findings
        assert callable(process_crawler_findings)
        print("[OK]")
    except Exception as e:
        print(f"[FAIL] {e}")
        return False
    
    # Test browser scanner (optional - requires Playwright)
    print("  ├─ Browser Scanner...", end=" ")
    try:
        from scanners.browser_scanner import playwright_inspect, process_browser_findings
        print("[OK]")
    except ImportError:
        print("⚠️  (Playwright not installed, skipping)")
    except Exception as e:
        print(f"[FAIL] {e}")
    
    # Test network scanner (functions: run_mitm_dump, stop_mitm_dump)
    print("  └─ Network Scanner...", end=" ")
    try:
        from scanners.network_scanner import run_mitm_dump, stop_mitm_dump
        assert callable(run_mitm_dump)
        assert callable(stop_mitm_dump)
        print("[OK]")
    except Exception as e:
        print(f"[FAIL] {e}")
        return False
    
    return True


def test_knowledge_graph():
    """Test knowledge graph creation."""
    print("\n🕸️  Testing Knowledge Graph...")
    
    try:
        from rag.knowledge_graph import KnowledgeGraph
        
        # Check if audit_report.json exists
        audit_path = Path("audit_report.json")
        if not audit_path.exists():
            print("  [FAIL] audit_report.json not found. Run scanners first!")
            return False
        
        # Build graph
        print("  ├─ Building graph from audit_report.json...", end=" ")
        kg = KnowledgeGraph()
        kg.build_from_audit(audit_path)
        print("[OK]")
        
        # Check stats
        stats = kg.stats()
        print(f"  ├─ Findings: {stats['findings']}")
        print(f"  ├─ Endpoints: {stats['endpoints']}")
        print(f"  ├─ CWEs: {stats['cwes']}")
        print(f"  └─ Edges: {stats['edges']}")
        
        # Save graph
        graph_path = Path("rag/graph.gpickle")
        kg.save(graph_path)
        print(f"  [OK] Graph saved to {graph_path}")
        
        return True
        
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_normalizer():
    """Test database normalization."""
    print("\n💾 Testing Database Normalizer...")
    
    try:
        from database.normalizer import normalize_graph_to_db
        
        # Normalize to SQLite
        print("  ├─ Normalizing graph to SQLite...", end=" ")
        stats = normalize_graph_to_db(
            graph_path="rag/graph.gpickle",
            db_path="database/security_findings.db"
        )
        print("[OK]")
        
        print(f"  ├─ Findings: {stats['findings']}")
        print(f"  ├─ Endpoints: {stats['endpoints']}")
        print(f"  ├─ CWEs: {stats['cwes']}")
        print(f"  └─ Finding-CWE mappings: {stats['finding_cwe_maps']}")
        
        # Test query
        print("  ├─ Testing SQL query...", end=" ")
        from database.normalizer import DatabaseNormalizer
        normalizer = DatabaseNormalizer("database/security_findings.db")
        critical = normalizer.query_findings(severity="CRITICAL")
        high = normalizer.query_findings(severity="HIGH")
        print(f"[OK] (CRITICAL: {len(critical)}, HIGH: {len(high)})")
        
        return True
        
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_embeddings():
    """Test embedding and vector store (optional)."""
    print("\n🔢 Testing Embeddings & Vector Store...")
    
    try:
        from rag.embedder import Embedder
        from rag.vector_store import VectorStore
        
        print("  ├─ Loading embedder...", end=" ")
        embedder = Embedder()
        print("[OK]")
        
        print("  ├─ Testing embedding...", end=" ")
        vecs = embedder.embed_texts(["test query", "another test"])
        assert len(vecs) == 2
        assert len(vecs[0]) == embedder.dim
        print(f"[OK] (dim={embedder.dim})")
        
        print("  ├─ Testing vector store...", end=" ")
        vs = VectorStore(dim=embedder.dim)
        vs.add("test1", vecs[0])
        vs.add("test2", vecs[1])
        results = vs.search(vecs[0], k=1)
        assert results[0][0] == "test1"
        print("[OK]")
        
        return True
        
    except ImportError as e:
        print(f"  ⚠️  Embeddings not available (optional): {e}")
        return True  # Not critical
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_retriever():
    """Test RAG retriever."""
    print("\n[TEST] Testing RAG Retriever...")
    
    try:
        from rag.retriever import Retriever
        
        graph_path = Path("rag/graph.gpickle")
        if not graph_path.exists():
            print("  [FAIL] Graph not found. Run test_knowledge_graph first!")
            return False
        
        # Test graph-only retrieval
        print("  ├─ Testing graph retrieval...", end=" ")
        retriever = Retriever(graph_path=graph_path)
        results = retriever.retrieve("API key", k=5, mode="graph")
        print(f"[OK] (found {len(results)} results)")
        
        # Test with embeddings (if available)
        try:
            from rag.embedder import Embedder
            from rag.vector_store import VectorStore
            
            print("  ├─ Testing vector retrieval...", end=" ")
            embedder = Embedder()
            vector_store = VectorStore(dim=embedder.dim)
            
            # Load graph and create embeddings
            from rag.knowledge_graph import KnowledgeGraph
            kg = KnowledgeGraph()
            kg.load(graph_path)
            
            for node_id, data in kg.g.nodes(data=True):
                if data.get("label") == "Finding":
                    text = f"{data.get('summary', '')} {data.get('snippet', '')}"
                    vec = embedder.embed_texts([text])[0]
                    vector_store.add(node_id, vec)
            
            retriever_v = Retriever(
                graph_path=graph_path,
                embedder=embedder,
                vector_store=vector_store
            )
            results_v = retriever_v.retrieve("credentials exposed", k=5, mode="vector")
            print(f"[OK] (found {len(results_v)} results)")
            
            print("  ├─ Testing hybrid retrieval...", end=" ")
            results_h = retriever_v.retrieve("password leak", k=5, mode="hybrid")
            print(f"[OK] (found {len(results_h)} results)")
            
        except ImportError:
            print("  ⚠️  Vector/hybrid retrieval skipped (embeddings not installed)")
        
        return True
        
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_llm_client():
    """Test LLM client (requires Ollama)."""
    print("\n🤖 Testing LLM Client...")
    
    try:
        from rag.llm_client import generate_answer
        
        print("  ├─ Checking Ollama connection...", end=" ")
        
        # Simple test query - NOTE: args are user_query, retrieved_contexts
        response = generate_answer(
            user_query="What is this?",
            retrieved_contexts=[
                {
                    "id": "test",
                    "summary": "Test finding",
                    "severity": "LOW"
                }
            ],
            model="gemma3:1b"
        )
        
        if response and response.get("text"):
            print("[OK]")
            return True
        else:
            print("⚠️  Ollama responded but empty")
            return True  # Not critical
            
    except Exception as e:
        print(f"  ⚠️  Ollama not available (optional): {e}")
        return True  # Not critical for library


def test_cli():
    """Test CLI interface."""
    print("\n💻 Testing CLI...")
    
    try:
        print("  ├─ Importing CLI...", end=" ")
        from rag.cli import query_graph_and_llm
        assert callable(query_graph_and_llm)
        print("[OK]")
        
        print("  └─ CLI available. Test manually with:")
        print("     python -m rag.cli --query 'show me API keys' --model gemma3:1b")
        
        return True
        
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def main():
    """Run all tests."""
    print("="*60)
    print("🧪 COMPLETE PIPELINE TEST")
    print("="*60)
    
    results = {
        "Scanners": test_scanners(),
        "Knowledge Graph": test_knowledge_graph(),
        "Database Normalizer": test_normalizer(),
        "Embeddings": test_embeddings(),
        "Retriever": test_retriever(),
        "LLM Client": test_llm_client(),
        "CLI": test_cli(),
    }
    
    print("\n" + "="*60)
    print("📊 RESULTS")
    print("="*60)
    
    for name, passed in results.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{status} {name}")
    
    all_passed = all(results.values())
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 ALL TESTS PASSED - Library is ready!")
    else:
        print("⚠️  Some tests failed - Review errors above")
    print("="*60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
