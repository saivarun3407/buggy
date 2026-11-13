---
name: llm-app-security
description: Hunt the OWASP Top 10 for LLM Applications — direct and indirect prompt injection, system-prompt and cross-tenant data leakage, and insecure tool/agent invocation (confused-deputy → SSRF/RCE/data access). Focuses on demonstrated security impact, not off-policy text.
metadata:
  subdomain: ai-security
  when_to_use: "llm ai application security owasp llm top 10 prompt injection indirect system prompt leak data leakage rag tool function invocation agent confused deputy excessive agency chatbot"
  mitre_attack: AML.T0051, AML.T0057, AML.T0053
---

# LLM / AI-App Security Playbook

As apps wire LLMs to tools, data, and actions, the model becomes an
authorization-bypass primitive — it often runs with more privilege than
the user. The finding is **what the user reached through it**, not the
prompt text. "I made it swear / ignore its persona" is rarely
reportable.

## 1. Map the LLM feature

For each chat / completion / agent / RAG feature, answer:

- What **tools/functions** can the model call?
- What **data** can it read (RAG corpus, user records, internal APIs)?
- What **actions** can it take (send email, make purchase, modify data)?
- Where does **untrusted input** enter — user, retrieved documents, web
  content, uploaded files?

## 2. Lane A — System-prompt & data leakage

Extract the system prompt and any embedded secrets/keys; probe RAG for
documents belonging to other tenants/users (cross-tenant leak = real
finding).

## 3. Lane B — Direct prompt injection

Override instructions to bypass guardrails toward a concrete action or
disclosure — chain to impact, not just a policy violation.

## 4. Lane C — Indirect / stored injection (high value)

Plant instructions in data the model will later ingest — a document,
profile field, web page, email — and show the model acts on them. This
is where agentic apps break.

## 5. Lane D — Insecure tool / agent invocation

The confused-deputy bug: drive the model to call a privileged tool with
attacker-chosen arguments:

- read another user's record (broken authZ via the model),
- fetch an internal/metadata URL (→ SSRF; coordinate with the SSRF
  specialist),
- run a command / access files (→ RCE / LFI).

Trace the injection to a real backend effect.

## 6. Proof & report

Show a concrete impact (data the user shouldn't see, an action they
shouldn't trigger). `bounty_scope_check`, then `report_hackerone` /
`report_bugcrowd_csv`. `payload_search` for injection payloads;
`web_search` for current LLM-app bug patterns.
