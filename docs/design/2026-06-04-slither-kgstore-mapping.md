# Slither `--json` → KGStore Mapping (RFC)

**Date:** 2026-06-04
**Status:** Draft — review required before implementation
**Scope:** CONTRACT_TOOLS (`packages/buggy/buggy/tools/contracts/`) migration from the legacy `_state` shim + in-memory `KnowledgeGraph` to direct `KGStore.record_observations` calls.
**Out of scope:** AD operator migration (see companion RFC `2026-06-04-bloodhound-kgstore-mapping.md`).

---

## 1. Why this RFC exists

After PR #549 the contract auditor's Slither ingestion still works through the legacy `_state` shim — the shim translates `_load → mutate → _save` into `KGStore.record_observations` calls so `tools/contracts/slither.py` did not need to change. That removes the broken `Neo4jStore` backend but leaves three real gaps:

1. **Schema fidelity** — Slither's `--json` output has 11 distinct element types (`contract`, `function`, `variable`, `node`, `pragma`, `enum`, `struct`, `event`, `custom_error`, `file`, plus the implicit `source_mapping.filename_relative` file scope). The current Buggy ingest collapses everything onto a single `Vulnerability` node. Path / chain analysis cannot distinguish "the same reentrancy spans both `withdraw()` and `deposit()`" from "two separate findings".
2. **Stable detector ID not used** — Slither emits a `id` field per finding that is a SHA3-256 hash over the concatenated element descriptions. It is stable across re-runs of the same code. Using it as the dedupe key gives idempotent re-ingest; the current code keys on a constructed string and re-creates Vulnerability nodes every run.
3. **Multi-location findings collapse to a single node** — a reentrancy can list N elements (the call site, the storage write, the function). The right modelling is **one Vulnerability node + N `AFFECTS` edges to Contract / Function / StateVar / CodeLocation**. The current code emits per-element vuln duplicates.

This RFC scopes the faithful Slither → KGStore mapping and proposes a phased migration that pairs with the BloodHound RFC for the contract auditor counterpart.

---

## 2. Slither `--json` ground truth

Sources (verified 2026-06-04):

- `crytic/slither` repo: `slither/utils/output.py` (output schema source of truth)
- `crytic/slither` wiki: [JSON output](https://github.com/crytic/slither/wiki/JSON-output)
- `crytic/slither` wiki: [Detector Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)

### 2.1 Top-level envelope

```json
{
  "success": true,
  "error": null,
  "results": {
    "detectors": [ /* finding objects */ ],
    "upgradeability-check": { /* optional */ }
  }
}
```

- `success = false` ⇒ `error` is a string + `results` may be empty/absent. Publisher MUST short-circuit on `success = false`; do not partial-ingest.
- `upgradeability-check` lives parallel to `detectors` with a different schema (proxy / impl diff). Branch in the parser — do NOT feed through the detector pipeline.

### 2.2 Detector finding object

```json
{
  "check": "reentrancy-eth",
  "impact": "High",
  "confidence": "Medium",
  "description": "...",
  "markdown": "...",
  "first_markdown_element": "src/X.sol#L10-L20",
  "id": "<sha3_256 hex>",
  "elements": [ ... ],
  "additional_fields": { ... }
}
```

- `impact ∈ {High, Medium, Low, Informational, Optimization}` — 5-tier (the wiki shows ~85 detectors).
- `confidence ∈ {High, Medium, Low}`.
- `id` is **stable across reruns of the same source**: hashes element descriptions, not random. **Use this as the dedupe `key`.**
- `additional_fields` is detector-specific bag — preserve as-is in props.

### 2.3 Element object

```json
{
  "type": "contract|function|variable|node|pragma|enum|struct|event|custom_error|file",
  "name": "withdraw",
  "source_mapping": {
    "start": 1024,
    "length": 158,
    "filename_relative": "src/Vault.sol",
    "filename_absolute": "/work/src/Vault.sol",
    "filename_short": "Vault.sol",
    "filename_used": "src/Vault.sol",
    "lines": [42, 43, 44, 45],
    "starting_column": 5,
    "ending_column": 6
  },
  "type_specific_fields": {
    "parent": { /* nested element, recursive */ },
    "signature": "withdraw(uint256)"
  },
  "additional_fields": {}
}
```

Per-type details:

| `type` | `type_specific_fields` |
|---|---|
| `contract` | `{}` |
| `function` | `parent` (the contract) + `signature` |
| `event` | `parent` + `signature` |
| `custom_error` | `parent` + `signature` |
| `variable` | `parent` (contract or function) |
| `enum` / `struct` / `node` | `parent` |
| `pragma` | `directive: "solidity ^0.8.0"` (no parent) |
| `file` | (no parent) |

### 2.4 Mapping table (provisional)

| Slither field | KGStore `kind` | `key` rule | Core props |
|---|---|---|---|
| `results.detectors[i]` (finding) | `Vulnerability` | `f"vuln::{check}::{id}"` (uses Slither's stable hash) | `check, impact, confidence, description, markdown, first_markdown_element, detector_category, slither_id, additional_fields` |
| `element` where `type=="contract"` | `Contract` | `f"contract::{filename_relative}::{name}"` | `name, filename, lines, source_mapping_abs` |
| `element` where `type=="function"` | `Function` | `f"function::{filename_relative}::{parent.name}::{signature}"` | `signature, name, parent_contract, lines, visibility?` |
| `element` where `type=="variable"` | `StateVar` | `f"var::{filename_relative}::{parent.name}::{name}"` | `name, parent_contract, lines` |
| `element` where `type=="node"` | `CodeLocation` | `f"node::{filename_relative}::{start}::{length}"` | `lines, start, length, parent_function` |
| `element` where `type=="pragma"` | `Pragma` | `f"pragma::{filename_relative}::{directive}"` | `directive, lines` |
| `element` where `type=="event"` | `Event` | `f"event::{filename_relative}::{parent.name}::{signature}"` | `signature, parent_contract` |
| `element` where `type=="custom_error"` | `CustomError` | `f"customerror::{filename_relative}::{parent.name}::{signature}"` | `signature, parent_contract` |
| `element` where `type=="enum"` | `Enum` | `f"enum::{filename_relative}::{parent.name}::{name}"` | `name, parent_contract` |
| `element` where `type=="struct"` | `Struct` | `f"struct::{filename_relative}::{parent.name}::{name}"` | `name, parent_contract` |
| `source_mapping.filename_relative` | `SourceFile` | `f"file::{filename_relative}"` | `path, sha256?` |

### 2.5 Edges

| Edge | From | To | Source |
|---|---|---|---|
| `AFFECTS` | `Vulnerability` | `Contract` / `Function` / `StateVar` / `CodeLocation` / `Pragma` | `finding.elements[]` — one edge per element |
| `DEFINED_IN` | `Function` / `StateVar` / `Event` / `CustomError` / `Enum` / `Struct` | `Contract` | `element.type_specific_fields.parent` (walk recursively) |
| `CONTAINED_IN` | `Contract` / `Function` / `StateVar` / `Pragma` / etc. | `SourceFile` | `source_mapping.filename_relative` |
| `CALLS` | `Function` | `Function` | Slither `function-summary --json -` printer (separate run; not in detector JSON) |

### 2.6 Traps (must handle in ingest)

1. **Same vuln, multiple locations.** A finding can list N elements (reentrancy spans both call site + storage write). Emit **one `Vulnerability` + N `AFFECTS` edges**, NOT N separate vulns.
2. **Recursive `parent`.** `parent` nests arbitrarily (node → function → contract). Walk recursively until `type == "contract"` to derive owning contract; do not assume depth=1.
3. **Filename variant choice.** All four (`filename_relative`, `_absolute`, `_short`, `_used`) are emitted. Canonical key = `filename_relative` (absolute leaks host fs into engagement-scoped data; `filename_used` can be IDE-normalised). Store the absolute under a separate `_abs` prop if needed.
4. **`lines` is NOT a `[start, end]` range.** It is a **list of individual line numbers** (`[42, 43, 44, 45]`). Iterating as a range silently misses multi-line functions with gaps.
5. **Stable `id` is per-finding, not per-element.** Element keys need their own composition (filename + parent + name). Don't try to reuse the Slither hash for element dedup.
6. **Visibility / modifier metadata absent from `--json` detectors.** Function elements carry `signature` only. To populate `visibility`, `payable`, `view/pure` you must run `slither --print function-summary --json -` separately and join on `signature` — a separate ingest step.
7. **`upgradeability-check`** is parallel to `detectors` with a proxy/impl diff schema. Different parser path; don't feed through the detector pipeline.
8. **`pragma`** elements lack `parent`. Don't assume every element has a contract context — attach pragma / file directly to `SourceFile`.
9. **`Impact == "Optimization"`** is wiki-only; some Slither versions emit it lowercased in JSON. Normalise (`.title()`) before storing.
10. **Oracle detectors are new (2024–2025).** `chronicle-unchecked-price`, `pyth-unchecked-confidence`, `pyth-unchecked-publishtime`, `pyth-deprecated-functions`, `chainlink-feed-registry`, `gelato-unprotected-randomness`. Add to the `check` allowlist so KGStore doesn't silently drop them; consider a `category=oracle` derived prop for analyst queries.

---

## 3. Architecture decision: how to represent Slither nodes in KGStore

Two options, mirroring the BloodHound RFC.

### Option A — Add Solidity-specific `NodeKind` values

`NodeKind` gains `STATE_VAR`, `FUNCTION`, `EVENT`, `CUSTOM_ERROR`, `ENUM`, `STRUCT`, `PRAGMA`. `Contract` already exists. `SOURCE_FILE` already exists.

**Pros**
- Cypher queries can filter precisely: `MATCH (v:Vulnerability)-[:AFFECTS]->(f:Function {visibility: "external"})`.
- ADCS / BloodHound nodes (RFC A) won't collide with Solidity entities — different label namespaces.
- Future tooling (Foundry trace ingest, Hardhat coverage, mythril output) can extend the Solidity node family without re-using overloaded kinds.

**Cons**
- `buggy-core` enum churn (~7 new values for the contract auditor on top of the AD RFC's 14).
- V003 / V004 migration must add composite-unique constraints + indexes per new label.

### Option B — Reuse existing kinds with `slither_type` prop

Keep `NodeKind` unchanged. Differentiate via a `slither_type` property (`slither_type="function"` on a `:CodeLocation` etc.).

**Pros**
- Zero `buggy-core` change.
- Existing test patches untouched.

**Cons**
- Function / variable / event / struct / enum / error all collapse into something generic — semantic loss.
- Cypher queries become `WHERE n.slither_type = "function"` instead of `MATCH (f:Function)`. Less readable, weaker indexes.
- Foundry / Hardhat tooling integration later becomes hostile: any tool that exports to Neo4j with proper labels won't be able to use the same graph.

### Recommendation

**Option A** — same reasoning as the BloodHound RFC. One-time enum churn vs ongoing compounded debt.

---

## 4. Phased migration plan (after this RFC is approved)

Each step lands as a separate PR. Steps depend on the BloodHound RFC's 4.1 (`NodeKind` / `EdgeKind` extension) being merged first so the core enum changes land atomically.

### 4.1 `NodeKind` extension for Solidity

- `buggy-core/types/kg.py`: add `STATE_VAR`, `FUNCTION`, `EVENT`, `CUSTOM_ERROR`, `ENUM`, `STRUCT`, `PRAGMA`. Add `EdgeKind.CALLS`.
- KGStore `V004__slither_schema.cypher`: composite uniqueness + per-label indexes.

### 4.2 Slither ingest core

- Rewrite `tools/contracts/slither.py` to emit observations via `KGStore.record_observations`:
  - One `Vulnerability` per `results.detectors[i]` keyed on the Slither stable `id`.
  - For each `element`: resolve type → emit corresponding node + `AFFECTS` edge.
  - Walk recursive `parent` chain to compute owning Contract + emit `DEFINED_IN`.
  - Attach every node to its `SourceFile` via `CONTAINED_IN`.
- Implement trap handlers from §2.6: multi-location vuln dedup, recursive parent, `lines`-as-list, Optimization normalisation, pragma special case.

### 4.3 Function-summary join (optional, follow-up)

- Add a wrapper that runs `slither --print function-summary --json -` and joins the per-function `visibility` / `payable` / `view-pure` info onto `Function` nodes by signature.
- Triggered after the main `slither_ingest` for an engagement.

### 4.4 Test migration + live validation

- Migrate `tests/unit/contracts/` to the observation API.
- Sample-data fixture: small Solidity project + golden Slither JSON + golden expected KGStore observations.
- `make dogfood` end-to-end: ingest into KGStore → contract_auditor agent queries → matches expected Findings.

### 4.5 Shim removal for Contract

- After 4.1 – 4.4 land, `tools/contracts/tools.py` no longer imports from `tools.research._state`.
- The `_state` shim stays in place for Research tools until their own migrations finish (a separate RFC).

---

## 5. Open questions

- **Foundry / Forge integration** — the contract auditor's PoC harness step runs Foundry tests. Should the Foundry trace data also flow into KGStore (as `:Function` nodes + `:CALLS` edges)? Recommend: yes, but as a separate follow-up RFC after Slither is solid.
- **mythril / echidna parallel ingest** — both can run alongside Slither. Each has its own JSON schema. Recommend: separate per-tool ingest modules sharing the same `Vulnerability` + `Contract` + `Function` node space — i.e. Option A pays off here.
- **Existing engagement data with the old single-node Vulnerability model** — do we offer a relabel script for engagements ingested by the current `slither_ingest`? Same answer as BloodHound: documented one-liner Cypher, no runtime auto-migration.

---

## 6. Sources

- [Slither JSON output wiki](https://github.com/crytic/slither/wiki/JSON-output)
- [Slither Detector Documentation](https://github.com/crytic/slither/wiki/Detector-Documentation)
- [crytic/slither · slither/utils/output.py](https://github.com/crytic/slither/blob/master/slither/utils/output.py)
- [Adding a new detector wiki](https://github.com/crytic/slither/wiki/Adding-a-new-detector)
