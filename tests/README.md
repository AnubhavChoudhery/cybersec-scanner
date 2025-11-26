# Test Suite Documentation

## Test Structure

```
tests/
├── test_knowledge_graph.py    # Graph building and persistence
├── test_cwe_enrichment.py     # CWE mapping validation  
├── test_normalizer.py          # Database normalization (5 tests)
├── test_retriever.py           # Graph-based retrieval (8 tests)
├── test_llm_client.py          # LLM generation with Ollama (9 tests)
└── test_end_to_end.py          # Full pipeline integration (2 tests)
```

## Prerequisites

### Core Requirements
```bash
pip install -r requirements.txt
```

### Ollama (for LLM tests)
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh  # Linux/Mac
# Or download from https://ollama.com for Windows

# Pull lightweight model
ollama pull gemma3:1b

# Verify running
ollama list
curl http://localhost:11434/api/tags
```

## Quick Test Commands

### Run All Tests
```bash
# Full test suite
pytest tests/ -v

# With coverage report
pytest tests/ --cov=rag --cov=database --cov-report=term-missing

# Parallel execution (faster)
pytest tests/ -v -n auto
```

### Run Specific Test Files
```bash
# Knowledge graph only
pytest tests/test_knowledge_graph.py -v

# CWE mapping only
pytest tests/test_cwe_enrichment.py -v

# Database normalization only
pytest tests/test_normalizer.py -v

# Retriever only
pytest tests/test_retriever.py -v

# LLM client only (requires Ollama)
pytest tests/test_llm_client.py -v

# End-to-end integration
pytest tests/test_end_to_end.py -v
```

### Skip LLM Tests (if Ollama not available)
```bash
# Skip LLM tests
pytest tests/ -v -k "not llm_client"

# Run only non-LLM tests
pytest tests/ -v --ignore=tests/test_llm_client.py
```

### Run Specific Test Cases
```bash
# Single test function
pytest tests/test_retriever.py::test_severity_ranking -v

# Multiple specific tests
pytest tests/test_retriever.py::test_tokenize tests/test_retriever.py::test_k_limit -v

# Pattern matching
pytest tests/ -v -k "severity"
pytest tests/ -v -k "empty or timeout"
```

## Test Categories

### Unit Tests (Fast)
```bash
# No external dependencies
pytest tests/test_knowledge_graph.py tests/test_cwe_enrichment.py tests/test_retriever.py -v
```

### Integration Tests (Medium)
```bash
# Database and graph interaction
pytest tests/test_normalizer.py tests/test_end_to_end.py -v
```

### LLM Tests (Slow, requires Ollama)
```bash
# Real LLM API calls
pytest tests/test_llm_client.py -v
```

## Coverage Reports

### Terminal Report
```bash
pytest tests/ --cov=rag --cov=database --cov-report=term-missing
```

### HTML Report
```bash
pytest tests/ --cov=rag --cov=database --cov-report=html
# Open htmlcov/index.html in browser
```

### Generate Coverage Badge
```bash
pytest tests/ --cov=rag --cov=database --cov-report=term-missing | grep TOTAL
```

## CI/CD Commands

### Pre-commit Checks
```bash
# Quick validation (no LLM)
pytest tests/ -v -k "not llm_client" --tb=short

# Full validation (with LLM)
pytest tests/ -v --tb=short
```

### GitHub Actions / CI Pipeline
```bash
# Fast fail on first error
pytest tests/ -v -x -k "not llm_client"

# Generate JUnit XML for CI
pytest tests/ -v --junitxml=test-results.xml -k "not llm_client"
```

## Troubleshooting

### Test Failures

**Issue: `ImportError: No module named 'rag'`**
```bash
# Ensure you're in project root
cd /path/to/Chrome_Ext
export PYTHONPATH=$PWD:$PYTHONPATH
pytest tests/ -v
```

**Issue: `FileNotFoundError: cwe_map.json`**
```bash
# Ensure CWE and OWASP maps exist
ls rag/cwe_map.json rag/owasp_map.json
```

**Issue: `OllamaError: Connection refused`**
```bash
# Start Ollama service
ollama serve  # Run in separate terminal

# Or skip LLM tests
pytest tests/ -v -k "not llm_client"
```

**Issue: Tests timeout**
```bash
# Increase timeout for slow systems
pytest tests/ -v --timeout=300
```

### Performance Issues

**Slow test execution:**
```bash
# Run in parallel (requires pytest-xdist)
pip install pytest-xdist
pytest tests/ -v -n auto
```

**LLM tests too slow:**
```bash
# Use faster model
pytest tests/test_llm_client.py -v  # Already uses gemma3:1b

# Or skip LLM tests entirely
pytest tests/ -v --ignore=tests/test_llm_client.py
```

## Continuous Testing

### Watch Mode
```bash
# Install pytest-watch
pip install pytest-watch

# Auto-run tests on file changes
ptw tests/ -- -v -k "not llm_client"
```

### Quick Feedback Loop
```bash
# Run only failed tests from last run
pytest tests/ -v --lf

# Run failed tests first, then all
pytest tests/ -v --ff
```

## Expected Test Counts

| Test File | Test Count | Duration |
|-----------|-----------|----------|
| test_knowledge_graph.py | 1 | < 1s |
| test_cwe_enrichment.py | 1 | < 1s |
| test_normalizer.py | 5 | ~2s |
| test_retriever.py | 8 | ~5s |
| test_llm_client.py | 8 | ~30s |
| test_end_to_end.py | 2 | ~3s |
| **TOTAL** | **24 tests** | **~40s** |

*LLM tests may take longer depending on model and system performance*
