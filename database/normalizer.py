"""
SQLite Normalization Layer for RAG System

Persists knowledge graph nodes and edges to SQLite database.
Enables SQL queries over findings, CWEs, and relationships.
"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
from datetime import datetime


class DatabaseNormalizer:
    """Normalizes knowledge graph into relational SQLite database."""
    
    def __init__(self, db_path: str = "database/security_findings.db"):
        """
        Initialize normalizer with database path.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema from schema.sql if needed."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        )
        if not cursor.fetchone():
            # Load and execute schema
            # Get schema.sql from same directory as this file
            schema_path = Path(__file__).parent / "schema.sql"
            if schema_path.exists():
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                cursor.executescript(schema_sql)
                conn.commit()
            else:
                # Fallback: create minimal tables inline
                cursor.executescript("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        snippet TEXT,
                        metadata JSON,
                        embedding_id INTEGER,
                        scan_id TEXT,
                        timestamp INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS cwe_entries (
                        cwe_id TEXT PRIMARY KEY,
                        name TEXT,
                        description TEXT,
                        severity TEXT,
                        metadata JSON
                    );
                    
                    CREATE TABLE IF NOT EXISTS endpoints (
                        id TEXT PRIMARY KEY,
                        url TEXT,
                        method TEXT,
                        first_seen INTEGER,
                        last_seen INTEGER
                    );
                    
                    CREATE TABLE IF NOT EXISTS finding_cwe_map (
                        finding_id TEXT,
                        cwe_id TEXT,
                        confidence REAL,
                        FOREIGN KEY (finding_id) REFERENCES findings(id),
                        FOREIGN KEY (cwe_id) REFERENCES cwe_entries(cwe_id)
                    );
                """)
                conn.commit()
        
        conn.close()
    
    def normalize_from_graph(self, graph_obj) -> Dict[str, int]:
        """
        Normalize knowledge graph into SQLite.
        
        Args:
            graph_obj: KnowledgeGraph instance with loaded graph
            
        Returns:
            Stats dict with counts of inserted records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {
            "findings": 0,
            "endpoints": 0,
            "cwes": 0,
            "finding_cwe_maps": 0
        }
        
        try:
            # Extract nodes by type
            for node_id, node_data in graph_obj.g.nodes(data=True):
                node_label = node_data.get("label")
                
                if node_label == "Finding":
                    self._insert_finding(cursor, node_id, node_data)
                    stats["findings"] += 1
                    
                elif node_label == "Endpoint":
                    self._insert_endpoint(cursor, node_id, node_data)
                    stats["endpoints"] += 1
                    
                elif node_label == "CWE":
                    self._insert_cwe(cursor, node_id, node_data)
                    stats["cwes"] += 1
            
            # Extract edges (relationships)
            for source, target, edge_data in graph_obj.g.edges(data=True):
                edge_label = edge_data.get("label")
                
                if edge_label == "is_instance_of":
                    # Finding -> CWE relationship
                    self._insert_finding_cwe_map(cursor, source, target)
                    stats["finding_cwe_maps"] += 1
            
            conn.commit()
        finally:
            conn.close()
        
        return stats
    
    def _insert_finding(self, cursor: sqlite3.Cursor, node_id: str, data: Dict):
        """Insert or update finding record."""
        cursor.execute("""
            INSERT OR REPLACE INTO findings (
                id, type, severity, source, summary, snippet, 
                metadata, scan_id, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            node_id,
            data.get("type", "unknown"),
            data.get("severity", "UNKNOWN"),
            data.get("source", "unknown"),
            data.get("summary", ""),
            data.get("snippet", "[REDACTED]"),
            json.dumps(data.get("metadata", {})),
            data.get("scan_id", "default"),
            data.get("timestamp", int(datetime.now().timestamp()))
        ))
    
    def _insert_endpoint(self, cursor: sqlite3.Cursor, node_id: str, data: Dict):
        """Insert or update endpoint record."""
        cursor.execute("""
            INSERT OR REPLACE INTO endpoints (
                id, url, method, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            node_id,
            data.get("url", ""),
            data.get("method", "GET"),
            data.get("first_seen", int(datetime.now().timestamp())),
            data.get("last_seen", int(datetime.now().timestamp()))
        ))
    
    def _insert_cwe(self, cursor: sqlite3.Cursor, node_id: str, data: Dict):
        """Insert or update CWE record."""
        cursor.execute("""
            INSERT OR REPLACE INTO cwe_entries (
                cwe_id, name, description, severity, metadata
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            node_id,
            data.get("name", ""),
            data.get("description", ""),
            data.get("severity", "UNKNOWN"),
            json.dumps(data.get("metadata", {}))
        ))
    
    def _insert_finding_cwe_map(
        self, 
        cursor: sqlite3.Cursor, 
        finding_id: str, 
        cwe_id: str,
        confidence: float = 1.0
    ):
        """Insert finding -> CWE relationship."""
        cursor.execute("""
            INSERT OR REPLACE INTO finding_cwe_map (
                finding_id, cwe_id, confidence
            ) VALUES (?, ?, ?)
        """, (finding_id, cwe_id, confidence))
    
    def query_findings(
        self, 
        severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query findings with optional filters.
        
        Args:
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            cwe_id: Filter by CWE ID
            limit: Max results to return
            
        Returns:
            List of finding dicts
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        cursor = conn.cursor()
        
        # Build query with optional filters
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if cwe_id:
            query += """ AND id IN (
                SELECT finding_id FROM finding_cwe_map WHERE cwe_id = ?
            )"""
            params.append(cwe_id)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
        
        return results
    
    def get_stats(self) -> Dict[str, int]:
        """Get database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        try:
            # Count findings
            cursor.execute("SELECT COUNT(*) FROM findings")
            stats["findings"] = cursor.fetchone()[0]
            
            # Count endpoints
            cursor.execute("SELECT COUNT(*) FROM endpoints")
            stats["endpoints"] = cursor.fetchone()[0]
            
            # Count CWEs
            cursor.execute("SELECT COUNT(*) FROM cwe_entries")
            stats["cwes"] = cursor.fetchone()[0]
            
            # Count relationships
            cursor.execute("SELECT COUNT(*) FROM finding_cwe_map")
            stats["finding_cwe_maps"] = cursor.fetchone()[0]
        finally:
            conn.close()
        
        return stats


def normalize_graph_to_db(graph_path: str = "rag/graph.gpickle", db_path: str = "database/security_findings.db"):
    """
    Convenience function to normalize a saved graph to database.
    
    Args:
        graph_path: Path to saved graph pickle file
        db_path: Path to SQLite database
        
    Returns:
        Stats dict
    """
    from rag.knowledge_graph import KnowledgeGraph
    
    # Load graph
    kg = KnowledgeGraph()
    kg.load(Path(graph_path))
    
    # Normalize to DB
    normalizer = DatabaseNormalizer(db_path)
    stats = normalizer.normalize_from_graph(kg)
    
    print(f"✅ Normalized to database: {stats}")
    return stats


if __name__ == "__main__":
    # CLI usage example
    import sys
    
    graph_path = sys.argv[1] if len(sys.argv) > 1 else "rag/graph.gpickle"
    db_path = sys.argv[2] if len(sys.argv) > 2 else "database/security_findings.db"
    
    stats = normalize_graph_to_db(graph_path, db_path)
    
    # Query some findings
    normalizer = DatabaseNormalizer(db_path)
    critical = normalizer.query_findings(severity="CRITICAL", limit=5)
    
    print(f"\n🔥 Critical findings ({len(critical)}):")
    for finding in critical:
        print(f"  - {finding['summary']} [{finding['type']}]")
