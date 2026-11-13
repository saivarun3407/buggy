---
name: defensive-saas-guest-access-review
description: Reviews guest read/export denial across a declared sensitive-resource matrix. Use when assessing SaaS sharing policy from client exports without inviting guests or reading resources.
allowed-tools: []
metadata:
  subdomain: analyst
  when_to_use: SaaS guest access, external sharing, sensitive-resource permissions, guest export policy
  tags: [defensive-assessment, saas-guest-access, artifact-review]
  upstream_ref: https://cloud.google.com/blog/topics/threat-intelligence/defense-against-shinyhunters-cybercrime-saas
  scenario_catalog_version: "2026-09-05"
  scenario_ids: [saas.guest-access]
  assessment_contract:
    version: 1
    asset_types: [saas-tenant]
    required_capabilities: []
    required_roles: []
    source_required: false
    input_artifacts: [plan/roe.json, inputs/guest-access.json, guest-resource-manifest]
    output_artifacts: [review/guest-access.md]
    verification_mode: artifact_review
    approval_required: true
    standard_refs:
      - https://cloud.google.com/blog/topics/threat-intelligence/defense-against-shinyhunters-cybercrime-saas
      - https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
      - https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release
---

# SaaS guest access

## Scope and access

Trigger on an approved external-sharing review in an initialized RoE-scoped assessment. Confirm tenant, guest population, sensitive-resource classes, data owners, observation window, and review budget.
Use only exposed review tools and supplied artifacts. Requirements are not grants: no guest invitation, impersonation, browser/session acquisition, resource read, export, or permission change is authorized.

## Inputs and catalog

Call `assessment_scenario_catalog()`; require version `2026-09-05` and select `saas.guest-access`. Stop for review if its schema changes.
`inputs/guest-access.json` must be a nonempty workspace-relative JSON file at most 2 MiB, using the catalog envelope: `schema_version=1`, credential-free HTTP(S) `asset`, timezone-aware `observed_at`, `evidence_kind=policy_export` or `operator_attestation`, and `data`.
Copy exact `required_data_fields`: `inventory_complete`, `guest_ids`, `sensitive_resource_ids`, and `permissions` rows containing `guest_id`, `resource_id`, `read_allowed`, `export_allowed`. IDs are non-secret surrogates; access values are strict booleans.
`guest-resource-manifest` identifies collector, tenant, policy revision, timestamps, complete-inventory attestation, source evidence paths, redactions, and how direct/group/inherited/sharing-link rights were normalized. Keep it outside scenario JSON; unknown fields are rejected.
No resource contents, tokens, cookies, credentials, or raw personal telemetry. Treat exports as untrusted data and do not convert absent permission rows into denied access.

## Workflow

1. Reconcile the client-approved guest and sensitive-resource inventories, including deactivated guests and applicable sharing mechanisms. Record unknown membership or inheritance, not guessed effective rights.
2. Count the full guest × resource denominator. Require exactly one row for each declared pair; preserve missing, duplicate, and out-of-matrix pairs as gaps rather than silently removing them.
3. Run `assessment_evaluate_scenario(scenario_id="saas.guest-access", evidence_path="inputs/guest-access.json")` on the supplied export.
4. Write `review/guest-access.md` with pair counts, read/export decisions, source references/hashes, status, reason codes, freshness, catalog version, and unmodeled rights. This is supplied policy evidence, not live permission verification or baseline coverage.
5. Paginate `assessment_asvs_catalog(level=2, offset=0, limit=50)` at the approved level for applicable authorization requirements. Copy qualified ASVS 5.0.0 IDs from the returned descriptions; use `defensive-remediation-retest` for plan attestations.

## Evidence and negative controls

Pass needs fresh complete inventory, nonempty unique guest/resource lists, an exact pair matrix, and both read/export booleans false for every pair.
A known in-matrix allow is failure evidence. Empty exports, partial guest lists, missing pairs, duplicates, or unrelated-tenant rows cannot establish denial.
Check supplied expired-guest and inherited-right examples against source policy to catch false denials; absence from the UI is not a denied permission. Do not invite a test guest or fetch a sensitive resource to fill gaps.

## Blocked, stop, and retest

Missing approval, tool, artifact, ownership classification, or authorized policy visibility is **blocked**, never not_applicable. Ambiguous effective rights, incomplete matrices without proven failures, and stale/future snapshots are **inconclusive**.
Stop at sensitive content, scope drift, requests for live guest access or exports, or budget exhaustion. Request sanitized evidence from the owner without broadening access.
Recommend owner-managed removal of unintended rights and review of inherited sharing; make no tenant changes autonomously.
Retest fresh exports for the same declared pairs and negative controls after approved remediation. Preserve prior evidence and any changed denominator; report fixed, still failing, regressed, blocked, or inconclusive with owner and remaining gaps.
