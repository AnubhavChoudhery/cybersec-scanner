# Database Layer

This directory contains the SQLite normalization layer for persisting knowledge graph data.

## Files

- **schema.sql**: Database schema (findings, CWE entries, endpoints, relationships)
- **normalizer.py**: Python module to normalize knowledge graph into SQLite
- **security_findings.db**: SQLite database (auto-created, gitignored)

## Usage

### Normalize a Knowledge Graph to Database

```python
from database.normalizer import normalize_graph_to_db

# Normalize saved graph
stats = normalize_graph_to_db(
    graph_path="rag/graph.gpickle",
    db_path="database/security_findings.db"
)

print(stats)
# {'findings': 42, 'endpoints': 15, 'cwes': 8, 'finding_cwe_maps': 42}
```

### Query Findings from Database

```python
from database.normalizer import DatabaseNormalizer

normalizer = DatabaseNormalizer("database/security_findings.db")

# Get all critical findings
critical = normalizer.query_findings(severity="CRITICAL", limit=10)

for finding in critical:
    print(f"{finding['severity']}: {finding['summary']}")

# Get findings mapped to specific CWE
cwe_798_findings = normalizer.query_findings(cwe_id="CWE-798", limit=10)

# Get database statistics
stats = normalizer.get_stats()
print(f"Total findings: {stats['findings']}")
```

### CLI Usage

```bash
# Normalize graph to database
python -m database.normalizer rag/graph.gpickle database/security_findings.db

# Query from Python REPL
python -c "from database.normalizer import DatabaseNormalizer; n = DatabaseNormalizer(); print(n.get_stats())"
```

## Schema Overview

### Core Tables

**findings**
- Stores vulnerability findings with severity, summary, snippet
- Links to embeddings via `embedding_id`
- Groups findings by `scan_id`

**cwe_entries**
- Common Weakness Enumeration catalog
- Links findings to standardized weakness types

**endpoints**
- HTTP endpoints where vulnerabilities were found
- Tracks first_seen and last_seen timestamps

**finding_cwe_map**
- Many-to-many relationship between findings and CWEs
- Includes confidence score for classification

## Integration with RAG Pipeline

1. **Build Graph**: `rag/knowledge_graph.py` creates NetworkX graph
2. **Normalize**: `database/normalizer.py` persists to SQLite
3. **Query**: SQL queries enable fast filtering by severity, CWE, etc.
4. **Retrieve**: `rag/retriever.py` can query database directly for structured queries

## Why SQLite?

- **Local-only**: No external database server required
- **Zero-config**: Works out of the box on all platforms
- **Fast**: Indexed queries on millions of findings
- **Portable**: Single file, easy to backup/share
- **SQL power**: Complex queries without loading full graph

## Future Enhancements

- [ ] Full-text search on summaries/snippets
- [ ] Time-series analysis of findings over multiple scans
- [ ] OWASP Top 10 mappings (table exists in schema)
- [ ] Mitigation recommendations (table exists in schema)
- [ ] CVE cross-references (table exists in schema)
