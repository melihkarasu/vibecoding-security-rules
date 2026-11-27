# AI, LLM, RAG & MCP Security Guide

**Scope:** Prompt Injection (Direct & Indirect), RAG Multi-Tenant Isolation, MCP Tool Hardening, Agent Sandboxing, LLM Output Handling.
**Related WSS Rules:** `AI-SEC-001`..`AI-SEC-010`, `redaction.py`.

## 1. Prompt & Data Boundary Separation (`AI-SEC-007`)
- **Never concatenate untrusted content into system prompts:** Keep external webpages, emails, retrieved RAG chunks, and tool outputs strictly inside user/tool message roles with explicit data delimiters.
- **Treat model output as untrusted input:** Every value returned by an LLM (SQL, shell arguments, URLs, HTML, JSON) must pass deterministic schema validation and allowlists before execution.

## 2. RAG & Vector Database Tenant Isolation (`AI-SEC-006`)
- **Mandatory tenant metadata filter:** Every vector search (`similarity_search`, Qdrant/Pinecone/Chroma/pgvector queries) MUST enforce a server-derived `filter={"tenant_id": auth.tenant_id}` (or per-tenant namespace/collection).
- **Document-level ACL check:** Re-verify document read permissions after vector retrieval and before injecting snippets into the LLM context window.

## 3. MCP & Tool-Calling Hardening (`AI-SEC-008`, `AI-SEC-009`)
- **No raw shell/eval in tool handlers:** Never pass LLM/MCP `arguments` into `subprocess(..., shell=True)`, `os.system()`, `exec()`, or `eval()`. Use parameterized APIs and strict enum/regex validation.
- **Tool SSRF protection:** Any AI/MCP tool that fetches URLs must enforce DNS resolution + private IP blocking (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.169.254`, `fc00::/7`) and `ScopePolicy` allowlists.
- **Bounded agent loops (`AI-SEC-008`):** Always cap `max_iterations` / `max_steps`, token budgets, and per-tool rate limits to prevent infinite agent loops and cost exhaustion.
- **Human-in-the-loop for destructive actions:** Require explicit confirmation for writes, deletes, external messages, or credentialed mutations.

## 4. LLM Output Rendering & Secret Redaction (`AI-SEC-010`)
- **Sanitize Markdown/HTML:** Never write raw LLM completions to `innerHTML` or `dangerouslySetInnerHTML`. Render via safe Markdown parsers with HTML disabled or sanitize via Sanitizer API / DOMPurify.
- **Pre-prompt & log redaction:** Run `redaction.redact_obj` / `sanitize_evidence` before sending source code, HTTP logs, or user records to external LLM APIs or writing scan history.
