"""
RAG (Retrieval Augmented Generation) system for vulnerability analysis.

This module provides:
- KnowledgeGraph: Build and manage vulnerability knowledge graphs
- Retriever: Semantic search over vulnerabilities
- LLM integration: Generate remediation guidance
"""

from .knowledge_graph import KnowledgeGraph
from .retriever import Retriever
from .llm_client import generate_answer
from .cli import query_graph_and_llm

__all__ = [
    "KnowledgeGraph",
    "Retriever",
    "generate_answer",
    "query_graph_and_llm",
]
