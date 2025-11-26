# Library Conversion TODO

## Phase 1: Today - Core Library Enhancements

### ✅ Completed
- [x] RAG system with graph, retriever, embeddings, LLM
- [x] SQLite normalization layer
- [x] Hybrid search (graph + vector + hybrid modes)
- [x] 12 passing unit & integration tests
- [x] GitHub Actions CI pipeline

### 🔧 Today - Critical for Library

#### 1. **API Documentation & Docstrings**
- [ ] Add comprehensive docstrings to all public functions
- [ ] Add type hints everywhere
- [ ] Create `docs/api_reference.md`
- [ ] Add usage examples in docstrings

#### 2. **Error Handling & Validation**
- [ ] Add proper exception classes (`SecurityScanError`, `RAGError`, etc.)
- [ ] Validate inputs (file paths, query strings, etc.)
- [ ] Add helpful error messages
- [ ] Handle missing dependencies gracefully

#### 3. **Configuration Management**
- [ ] Create `Config` class for library settings
- [ ] Support config files (YAML/JSON)
- [ ] Environment variable support
- [ ] Default configurations that work out-of-box

#### 4. **Performance & Optimization**
- [ ] Add database indexes to SQLite schema
- [ ] Cache frequently accessed data
- [ ] Batch processing for large scans
- [ ] Progress callbacks for long operations

#### 5. **Testing Coverage**
- [ ] Check test coverage (`pytest --cov`)
- [ ] Add tests for error cases
- [ ] Add tests for edge cases (empty inputs, large files, etc.)
- [ ] Add performance/benchmark tests

#### 6. **Library Structure**
- [ ] Create `__init__.py` with public API
- [ ] Define `__version__`
- [ ] Export only public interfaces
- [ ] Hide internal implementation details

---

## Phase 2: Tomorrow - Library Packaging

### 📦 Package Structure
```
cybersec_scanner/
├── __init__.py              # Public API
├── __version__.py           # Version info
├── config.py                # Configuration
├── exceptions.py            # Custom exceptions
├── scanners/
│   ├── __init__.py
│   ├── git_scanner.py
│   ├── web_crawler.py
│   └── ...
├── rag/
│   ├── __init__.py
│   ├── knowledge_graph.py
│   ├── retriever.py
│   └── ...
├── database/
│   ├── __init__.py
│   ├── normalizer.py
│   └── schema.sql
└── utils/
    ├── __init__.py
    └── helpers.py
```

### 📄 Package Files
- [ ] `setup.py` or `pyproject.toml`
- [ ] `MANIFEST.in`
- [ ] `LICENSE` (MIT/Apache 2.0?)
- [ ] `README.md` (library usage)
- [ ] `CHANGELOG.md`
- [ ] `requirements.txt` → split to `requirements.txt` + `requirements-dev.txt`

### 📚 Documentation
- [ ] Quick start guide
- [ ] API reference
- [ ] Examples directory
- [ ] Advanced usage guide
- [ ] FAQ

### 🧪 Testing
- [ ] Test installation: `pip install -e .`
- [ ] Test in fresh venv
- [ ] Test example scripts work

### 🚀 Publishing
- [ ] Test PyPI upload (TestPyPI first)
- [ ] Create GitHub releases
- [ ] Write release notes

---

## Phase 3: Post-Release Enhancements

### 🎯 Library Features (Nice to Have)
- [ ] Async support (`async def scan_async()`)
- [ ] Streaming results (generator functions)
- [ ] Plugin system for custom scanners
- [ ] Export to multiple formats (JSON, SARIF, HTML)
- [ ] Differential scanning (compare two scans)

### 🔌 Integrations
- [ ] GitHub Action
- [ ] Pre-commit hook
- [ ] CI/CD webhook server

### 📊 Observability
- [ ] Structured logging
- [ ] Metrics/telemetry (opt-in)
- [ ] Progress bars (optional with `tqdm`)

---

## Today's Priority Tasks

### High Priority (Do These Today)
1. **Run full pipeline test**: `python test_full_pipeline.py`
2. **Add docstrings & type hints** to all public functions
3. **Create `exceptions.py`** with custom error classes
4. **Create `__init__.py`** with clean public API
5. **Check test coverage**: `pytest --cov=rag --cov=database --cov=scanners`
6. **Add input validation** to key functions

### Medium Priority (If Time)
7. Add database indexes to `schema.sql`
8. Create `Config` class
9. Add more error handling tests
10. Write `docs/LIBRARY_USAGE.md`

### Can Wait for Tomorrow
- Package structure refactoring
- setup.py creation
- Publishing prep

---

## Library Public API Design (Draft)

```python
# Simple usage
from cybersec_scanner import Scanner, RAGSystem

# 1. Scan
scanner = Scanner()
report = scanner.scan(
    git_repo=".",
    url="https://example.com",
    output="audit.json"
)

# 2. Query with RAG
rag = RAGSystem(report_path="audit.json")
answer = rag.query("Show me all API key leaks")
print(answer)

# 3. Database queries
from cybersec_scanner import Database

db = Database("findings.db")
critical = db.query_findings(severity="CRITICAL")
print(f"Found {len(critical)} critical issues")
```

Clean, simple, Pythonic! 🐍
