#!/bin/bash
# Example: Complete Security Audit Workflow with RAG Pipeline

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     COMPLETE SECURITY AUDIT WITH RAG PIPELINE                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
TARGET="http://localhost:8000"
BACKEND_ROOT="./backend"
MITM_TRAFFIC="$BACKEND_ROOT/app/mitm_traffic.ndjson"

# Check if Ollama is running
echo "Checking Ollama availability..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama is running"
    OLLAMA_AVAILABLE=true
else
    echo "⚠️  Ollama not running - LLM analysis will be skipped"
    echo "   Start with: ollama serve"
    OLLAMA_AVAILABLE=false
fi
echo ""

# Step 1: Quick scan without RAG
echo "════════════════════════════════════════════════════════════════"
echo "STEP 1: Quick Security Scan (no RAG)"
echo "════════════════════════════════════════════════════════════════"
echo "Running lightweight scan to identify vulnerabilities..."
echo ""

python local_check.py \
  --target "$TARGET" \
  --root "$BACKEND_ROOT" \
  --enable-git \
  --mitm-traffic "$MITM_TRAFFIC" \
  || true  # Don't fail on vulnerabilities

echo ""
echo "✅ Quick scan complete - check audit_report.json"
echo ""

# Step 2: Full scan with RAG analysis
echo "════════════════════════════════════════════════════════════════"
echo "STEP 2: Full Scan with RAG Pipeline"
echo "════════════════════════════════════════════════════════════════"
echo "Running complete scan with knowledge graph and LLM analysis..."
echo ""

python local_check.py \
  --target "$TARGET" \
  --root "$BACKEND_ROOT" \
  --enable-git \
  --enable-runtime \
  --enable-mitm \
  --enable-rag \
  --mitm-traffic "$MITM_TRAFFIC" \
  --rag-db "security_audit.db" \
  --llm-model "gemma3:1b" \
  || true  # Don't fail on vulnerabilities

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "SCAN COMPLETE - Generated Files"
echo "════════════════════════════════════════════════════════════════"
echo ""

# List generated files
ls -lh audit_report.json 2>/dev/null && echo "✅ audit_report.json - Raw scanner findings"
ls -lh rag/graph.gpickle 2>/dev/null && echo "✅ rag/graph.gpickle - Knowledge graph"
ls -lh security_audit.db 2>/dev/null && echo "✅ security_audit.db - SQLite database"
ls -lh rag_summary.txt 2>/dev/null && echo "✅ rag_summary.txt - LLM executive summary"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "INTERACTIVE ANALYSIS"
echo "════════════════════════════════════════════════════════════════"
echo ""

if [ "$OLLAMA_AVAILABLE" = true ]; then
    echo "Example queries you can run:"
    echo ""
    echo "  # Get vulnerability overview"
    echo "  python rag/cli.py --query \"What are the most critical vulnerabilities?\""
    echo ""
    echo "  # Ask about specific issue types"
    echo "  python rag/cli.py --query \"Show me all hardcoded credentials\""
    echo ""
    echo "  # Get remediation advice"
    echo "  python rag/cli.py --query \"How do I fix the API key exposures?\""
    echo ""
    echo "  # Check OWASP compliance"
    echo "  python rag/cli.py --query \"Which OWASP Top 10 categories are we violating?\""
    echo ""
else
    echo "⚠️  LLM queries unavailable (Ollama not running)"
    echo ""
fi

echo "Database queries:"
echo ""
echo "  # View critical findings"
echo "  sqlite3 security_audit.db \"SELECT severity, summary FROM findings WHERE severity='CRITICAL';\""
echo ""
echo "  # Count by severity"
echo "  sqlite3 security_audit.db \"SELECT severity, COUNT(*) FROM findings GROUP BY severity;\""
echo ""
echo "  # Export to CSV"
echo "  sqlite3 security_audit.db -csv -header \"SELECT * FROM findings;\" > findings.csv"
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "NEXT STEPS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. Review rag_summary.txt for LLM-generated executive summary"
echo "2. Use CLI to ask specific questions about vulnerabilities"
echo "3. Query database for filtered/sorted findings"
echo "4. Check RAG_USAGE.md for more examples and advanced usage"
echo ""
echo "Done! 🎉"
