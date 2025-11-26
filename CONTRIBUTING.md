# Contributing to CyberSec Scanner

Thank you for your interest in contributing to CyberSec Scanner! This guide will help you get started.

## Development Setup

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/yourusername/CyberSec_Chrome_Ext.git
   cd CyberSec_Chrome_Ext
   ```

2. **Install in editable mode**:
   ```powershell
   pip install -e ".[dev]"
   ```

3. **Verify installation**:
   ```powershell
   cybersec-scanner --version
   pytest
   ```

## Branch Strategy

### Main Branch Protection
- `main` branch is protected
- All changes must go through Pull Requests
- PRs require at least 1 review before merge
- Tests must pass before merge (CI enforced when GitHub Actions is set up)

### Feature Branches
Always create a feature branch for your work:

```powershell
# Create and switch to a new branch
git checkout -b feat/your-feature-name

# Examples:
git checkout -b feat/rag-cwe-enrichment
git checkout -b fix/graph-save-error
git checkout -b docs/setup-instructions
```

**Branch naming conventions**:
- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation only
- `refactor/` - Code refactoring
- `test/` - Test additions or fixes
- `chore/` - Maintenance tasks (deps, config)

## Commit Guidelines

### Atomic Commits
Each commit should represent a single logical change:

```powershell
# Good: One concept per commit
git commit -m "feat: add CWE mapping to knowledge graph"
git commit -m "test: add CWE enrichment unit tests"
git commit -m "docs: update SETUP.md with CWE instructions"

# Bad: Multiple unrelated changes
git commit -m "add CWE, fix bug, update docs, refactor retriever"
```

### Commit Message Format
```
<type>: <short summary>

<optional detailed description>

<optional footer with breaking changes, issue refs>
```

**Types**:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Test changes
- `refactor:` - Code refactoring
- `chore:` - Maintenance

**Examples**:
```
feat: add CWE-798 mapping for hardcoded credentials

- Add rag/cwe_map.json with 8 common CWE mappings
- Update KnowledgeGraph.add_finding to create CWE nodes
- Add is_instance_of edges from Finding to CWE

Closes #42
```

```
fix: resolve hnswlib import error on Windows

Falls back to numpy-based vector search when hnswlib
cannot be compiled due to missing C++ build tools.

Breaking: None
```

## Pull Request Process

### Before Opening a PR

1. **Run tests locally**:
   ```powershell
   pytest
   ```

2. **Ensure code runs without errors**:
   ```powershell
   # Test CLI commands
   cybersec-scanner --version
   cybersec-scanner init-config
   
   # Test SDK imports
   python -c "from cybersec_scanner import scan_all; print('OK')"
   ```

3. **Check for linting issues**:
   ```powershell
   # Run linters (CI will check these)
   black --check cybersec_scanner tests
   isort --check-only cybersec_scanner tests
   flake8 cybersec_scanner tests
   mypy cybersec_scanner
   ```

4. **Update relevant documentation**:
   - If you add a new feature, update `SETUP.md` or `RAG.md`
   - If you change APIs, update docstrings
   - If you add dependencies, update `requirements.txt`

### Opening the PR

```powershell
# Push your branch
git push origin feat/your-feature-name

# Open PR on GitHub
# Use the PR template (TBD) and fill in:
# - What changed
# - Why (motivation, issue link)
# - How to test
# - Screenshots (if UI changes)
```

### PR Title Format
Follow the same format as commit messages:
```
feat: add CWE enrichment to knowledge graph
fix: resolve hnswlib build error on Windows
docs: add comprehensive SETUP.md
```

### PR Description Template
```markdown
## Summary
Brief description of what this PR does.

## Motivation
Why is this change needed? Link to issue if applicable.

## Changes
- Bullet list of specific changes
- Include new files, modified files, deleted files

## Testing
Steps to test this PR:
1. Run `python -m pytest tests/test_cwe_enrichment.py`
2. Build graph: `python -c "from rag.build_graph import build_graph; print(build_graph('audit_report.json'))"`
3. Verify CWE nodes exist in graph

## Checklist
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] Dependencies added to requirements.txt (if any)
- [ ] No secrets or credentials committed
- [ ] Code is atomic (single feature/fix)
```

## When to Push (Safe Practices)

### ✅ Safe to Push
- **After tests pass locally**
- **After review by at least one other developer** (once PR is approved)
- **When commits are atomic and well-documented**
- **When dependencies are pinned in requirements.txt**
- **When no secrets are in the code** (use .env files, never commit credentials)

### ⚠️ Do NOT Push
- **Directly to `main` branch** (always use PR)
- **Without running tests**
- **Half-finished features** (use draft PRs instead)
- **Large binary files** (use .gitignore, Git LFS if needed)
- **Secrets, API keys, passwords** (NEVER commit these)

## Code Review Guidelines

### As a Reviewer
- **Be constructive**: Suggest improvements, don't just criticize
- **Test the changes**: Pull the branch and run tests locally
- **Check for security issues**: No hardcoded secrets, no SQL injection risks
- **Verify documentation**: Is the feature documented?
- **Approve only if**:
  - Tests pass
  - Code is clean and readable
  - No breaking changes without discussion
  - Documentation is updated

### As an Author
- **Respond to feedback quickly**
- **Don't take criticism personally** — it's about the code, not you
- **Update the PR** based on feedback
- **Rebase if needed**:
  ```powershell
  git fetch origin
  git rebase origin/main
  git push --force-with-lease
  ```

## Testing Requirements

### Unit Tests
Every new feature should have unit tests:

```python
# tests/test_my_feature.py
def test_my_feature():
    # Arrange
    input_data = {...}
    
    # Act
    result = my_function(input_data)
    
    # Assert
    assert result == expected_output
```

### Integration Tests
For end-to-end flows, add integration tests (future):

```python
# tests/test_end_to_end.py
def test_full_rag_pipeline():
    # Build graph -> retrieve -> LLM -> verify citations
    ...
```

### Test Coverage
- **Minimum**: 70% coverage for new code
- **Ideal**: 90%+ coverage
- Run coverage report (future):
  ```powershell
  pytest --cov=rag --cov-report=html
  ```

## Dependency Management

### Adding Dependencies
1. **Add to requirements.txt**:
   ```powershell
   pip install new-package
   pip freeze | grep new-package >> requirements.txt
   ```

2. **Pin versions** for reproducibility:
   ```txt
   # Good
   networkx==3.1
   ollama==0.1.7
   
   # Bad (unpinned)
   networkx
   ollama
   ```

3. **Document why** in PR description:
   - "Added `sentence-transformers` for embedding generation (required for semantic search)"

### Removing Dependencies
1. Remove from `requirements.txt`
2. Search for imports: `grep -r "import removed_package" .`
3. Test that nothing breaks: `python -m pytest`

## Security Guidelines

### Never Commit
- API keys
- Passwords
- Private keys
- `.env` files with secrets
- Database connection strings with credentials

### Use Environment Variables
```python
# Good
import os
api_key = os.getenv("OPENAI_API_KEY")

# Bad
api_key = "sk-1234567890abcdef"  # NEVER DO THIS
```

### Redact Secrets in Tests
```python
# Good
assert finding["snippet"] == "[REDACTED]"

# Bad
assert finding["snippet"] == "AKIA1234567890ABCDEF"  # Real AWS key
```

## CI/CD

GitHub Actions automatically runs on every push and PR:

### What CI Checks
- ✅ **Tests** (`pytest`) on Ubuntu, Windows, macOS with Python 3.8-3.12
- ✅ **Linting** (`black`, `isort`, `flake8`, `mypy`)
- ✅ **Build** verification (package builds correctly)
- ✅ **Coverage** uploaded to Codecov

### CI Workflows
- `.github/workflows/test.yml` - Multi-platform test matrix
- `.github/workflows/lint.yml` - Code quality checks
- `.github/workflows/build.yml` - Build verification
- `.github/workflows/publish.yml` - PyPI publishing (on release)

### CI Failures
If CI fails:
1. Check the logs on GitHub Actions
2. Reproduce locally: `pytest` or `black --check .`
3. Fix the issue
4. Push the fix: `git commit -m "fix: resolve CI test failure"`

## Release Process

See `RELEASE.md` for complete release documentation. Quick summary:

### Automated Release (Preferred)
1. Update version in `cybersec_scanner/__version__.py`
2. Update `CHANGELOG.md`
3. Commit and push to `main`
4. Create GitHub Release with tag (e.g., `v1.0.0`)
5. GitHub Actions automatically publishes to PyPI

### Manual Release
```powershell
# Build package
python -m build

# Upload to TestPyPI first
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ cybersec-scanner

# Upload to production PyPI
python -m twine upload dist/*
```

See `RELEASE.md` for detailed instructions including Trusted Publisher setup.

## Questions?

- Open a discussion on GitHub
- Ask in the team chat
- Review existing PRs for examples

## Code of Conduct

- Be respectful
- Be patient with new contributors
- Help others learn
- Give credit where due
- Report issues, don't work around them silently

---

**Thank you for contributing!** 🚀
