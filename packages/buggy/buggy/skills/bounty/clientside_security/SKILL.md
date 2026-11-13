---
name: client-side-injection
description: Hunt client-side bugs that execute in the victim's browser — DOM/reflected/stored XSS (confirmed by real browser execution), CORS misconfiguration with credentials, prototype pollution gadget chains, and postMessage origin-validation flaws.
metadata:
  subdomain: web-exploitation
  when_to_use: "xss cross site scripting dom reflected stored cors misconfiguration access-control-allow-origin credentials prototype pollution __proto__ postmessage origin client side javascript csp bypass"
  mitre_attack: T1059.007, T1539, T1189
---

# Client-Side Security Playbook

These bugs run in the victim's browser, so confirm them in a **real
browser** (the browser tool) — an unescaped reflection is a hypothesis,
not a finding.

## 1. Map sources → sinks

Attacker-controlled sources: URL params, fragment (`#`), `postMessage`,
`localStorage`/`sessionStorage`, and server-reflected values. Dangerous
sinks: `innerHTML`, `document.write`, `eval`, `setTimeout(str)`, jQuery
`$()`, framework `dangerouslySetInnerHTML`/`v-html`.

## 2. Lane A — DOM XSS

Taint-trace source → sink in the JS; identify the encoding/context at
the sink; craft a context-correct payload (HTML / attribute / JS / URL
context) that breaks out; load it in the browser and capture proof of
execution (callback hit or controlled DOM mutation).

## 3. Lane B — Reflected / stored XSS

Inject across contexts; for stored, confirm persistence **and** that it
fires for another user. Check CSP and bypass where weak (unsafe-inline,
overly broad `script-src`, JSONP endpoints, dangling markup).

## 4. Lane C — CORS / postMessage

- **CORS**: a permissive `Access-Control-Allow-Origin` is only a finding
  when paired with `Allow-Credentials: true` AND a sensitive
  authenticated response. Prove a cross-origin credentialed read.
- **postMessage**: find `message` listeners that don't validate
  `event.origin` and feed attacker data into a dangerous sink.

## 5. Lane D — Prototype pollution

Find `__proto__` / constructor merge sinks (client and SSR); chain to a
concrete gadget (DOM XSS, auth bypass, RCE in SSR) and report the
**gadget impact**, not the pollution primitive alone.

## 6. Reportability gate

Self-XSS and XSS that needs the victim to paste into devtools are not
reportable in most programs — chain to something delivered (URL, stored,
or CSRF-triggered) or drop it.

## 7. Proof & report

`bounty_scope_check`, then `report_hackerone` / `report_bugcrowd_csv`.
`payload_search` for XSS/polyglot payloads; `h1_search` for disclosed
client-side chains.
