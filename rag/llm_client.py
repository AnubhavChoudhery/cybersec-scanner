"""
Lightweight local LLM client for Ollama with simple response validation and secret redaction.

Behavior:
- Builds a prompt from system + retrieved contexts + user query
- Attempts three ways to call Ollama (python package, HTTP API, CLI fallback)
- Validates response: checks for citation tokens like "[Source:" and redacts secret-like patterns

Requirements: Ollama daemon must be running locally and the desired model installed.
HTTP API default: http://127.0.0.1:11434/api/generate
"""
from __future__ import annotations
import re
import json
import subprocess
from typing import List, Dict, Any, Optional

SYSTEM_PROMPT = """
You are a security expert analyzing vulnerability findings.
You MUST cite retrieved context using [Source: finding_id].
You MUST NOT expose any secret values or credentials.
You MUST provide actionable remediation steps.
"""

USER_PROMPT_TEMPLATE = """
Context (from retrieval):
{retrieved_contexts}

Query: {user_query}

Provide remediation following these rules:
1. Cite sources for every claim using [Source: finding_id]
2. Prioritize by severity (CRITICAL first)
3. Include code examples where applicable
4. Explain the security impact
"""

OLLAMA_HTTP = "http://127.0.0.1:11434/api/generate"

# Simple secret-like patterns to redact in responses (AWS keys, long base64 tokens, generic api keys)
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:ghp|gho)_[A-Za-z0-9_]{36}"),
    re.compile(r"[A-Za-z0-9-_]{40,}")  # long token-ish strings
]


class OllamaError(RuntimeError):
    pass


def _redact_secrets(text: str) -> str:
    replaced = text
    for p in _SECRET_PATTERNS:
        replaced = p.sub("[REDACTED]", replaced)
    return replaced


def _ensure_citation(text: str, retrieved_contexts: List[Dict[str, Any]]) -> str:
    # If the model didn't include citations, add a short note requesting them.
    if "[Source:" in text:
        return text
    # otherwise append citations mapping for available contexts
    if not retrieved_contexts:
        return text + "\n\n[NOTE] No retrieved contexts available to cite."
    cites = []
    for ctx in retrieved_contexts[:5]:
        fid = ctx.get("id") or ctx.get("finding_id") or ctx.get("source_id")
        if fid:
            cites.append(f"[Source: {fid}]")
    if cites:
        return text + "\n\nCitations: " + ", ".join(cites)
    return text


def _build_prompt(retrieved_contexts: List[Dict[str, Any]], user_query: str) -> str:
    ctx_texts = []
    for c in retrieved_contexts:
        # each context should include finding_id, summary, severity, url
        fid = c.get("id") or c.get("finding_id") or c.get("source_id")
        summary = c.get("summary") or c.get("description") or ""
        sev = c.get("severity", "INFO")
        url = c.get("url") or c.get("endpoint") or ""
        ctx_texts.append(f"[Source: {fid}] Severity: {sev} URL: {url} Summary: {summary}")
    retrieved_text = "\n".join(ctx_texts) if ctx_texts else "(no contexts)"
    prompt = SYSTEM_PROMPT + "\n" + USER_PROMPT_TEMPLATE.format(retrieved_contexts=retrieved_text, user_query=user_query)
    return prompt


def _call_ollama_http(model: str, prompt: str, timeout: int = 60) -> str:
    import requests
    payload = {"model": model, "prompt": prompt}
    try:
        resp = requests.post(OLLAMA_HTTP, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # Ollama HTTP response shapes vary; try a couple of options
        if isinstance(data, dict):
            # possible keys: 'result' or 'content' or 'text' or 'output'
            for key in ("result", "content", "text", "output", "response"):
                if key in data:
                    val = data[key]
                    if isinstance(val, str):
                        return val
                    try:
                        return json.dumps(val)
                    except Exception:
                        return str(val)
            # else fallback to join of values
            return json.dumps(data)
        return str(data)
    except Exception as e:
        raise OllamaError(f"HTTP Ollama call failed: {e}")


def _call_ollama_cli(model: str, prompt: str, timeout: int = 60) -> str:
    # Use `ollama generate` as a fallback. Requires ollama CLI in PATH and model installed.
    try:
        proc = subprocess.run(["ollama", "generate", model, prompt], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise OllamaError(f"ollama CLI failed: {proc.stderr.strip()}")
        return proc.stdout
    except FileNotFoundError:
        raise OllamaError("ollama CLI not found in PATH")
    except Exception as e:
        raise OllamaError(f"ollama CLI error: {e}")


def generate_answer(
    user_query: str,
    retrieved_contexts: List[Dict[str, Any]],
    model: str = "gemma3:1b",
    timeout: int = 60,
) -> Dict[str, Any]:
    """Generate a remediation answer using a local Ollama model.

    Returns a dict: {"text": str, "raw": any, "cited": bool}
    """
    prompt = _build_prompt(retrieved_contexts, user_query)

    # Try python ollama package first (if available)
    try:
        import ollama as _oll
        try:
            out = _oll.generate(model=model, prompt=prompt)
            # _oll.generate returns a dict with 'response' field containing the actual text
            if isinstance(out, dict) and 'response' in out:
                text = out['response']
            elif isinstance(out, str):
                text = out
            else:
                # Fallback: try to extract text from dict
                text = str(out.get('response', out.get('text', str(out))))
        except Exception:
            # fall through to HTTP
            text = _call_ollama_http(model, prompt, timeout=timeout)
    except Exception:
        # try HTTP API
        try:
            text = _call_ollama_http(model, prompt, timeout=timeout)
        except OllamaError:
            # try CLI fallback
            text = _call_ollama_cli(model, prompt, timeout=timeout)

    # Redact secrets
    redacted = _redact_secrets(text)

    # Ensure citations exist (or append notes)
    final = _ensure_citation(redacted, retrieved_contexts)

    cited = "[Source:" in final

    return {"text": final, "raw": text, "cited": cited}


if __name__ == "__main__":
    # small demo (requires running Ollama)
    example_ctx = [{"id": "f1", "summary": "AWS key in header", "severity": "CRITICAL", "url": "https://api.example.com"}]
    res = generate_answer("How to fix AWS key exposure?", example_ctx, model="gemma3:1b")
    print(res["text"]) 
