---
name: ssrf-cloud-metadata
description: Hunt Server-Side Request Forgery and escalate it — confirm via out-of-band callback, bypass filters (IP encodings, DNS rebinding, redirect/gopher smuggling), pivot to internal services, and (only when authorised) reach cloud-metadata endpoints for IAM credentials.
metadata:
  subdomain: web-exploitation
  when_to_use: "ssrf server side request forgery cloud metadata 169.254.169.254 imds imdsv2 iam credentials dns rebinding gopher redirect filter bypass internal pivot webhook url fetch"
  mitre_attack: T1190, T1552.005
---

# SSRF & Cloud-Metadata Playbook

SSRF is the gateway to the internal network and the cloud control plane.
A single SSRF into a metadata endpoint can yield IAM credentials and
full account compromise — but metadata is **off by default** here.

## 1. Scope gate (read first)

Cloud-metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, GCP
`metadata.google.internal`, Azure IMDS) are out-of-scope by default and
blocked at the sandbox edge. Only target them when the program
explicitly authorises metadata testing **and** scope was ingested with
`ingest_bounty_scope(allow_cloud_metadata=True)`. Otherwise prove SSRF
reach with an in-scope / out-of-band target instead.

## 2. Lane A — Find URL sinks

Webhooks, link previews, PDF/image fetchers, import-from-URL, SSO
metadata URLs, file-upload-via-URL, and any param that smells like a
URL/host.

## 3. Lane B — Confirm (always before claiming)

Inject a collaborator URL you control; confirm server-side fetch via an
out-of-band DNS/HTTP hit (`interactsh`-style listener). A 500 error is
**not** proof.

## 4. Lane C — Filter bypass

Alternate IP encodings (decimal, octal, IPv6-mapped), `@`-confusion in
the authority, open-redirect chaining, DNS rebinding, and
`gopher://`/`dict://` smuggling where the fetcher allows it.

## 5. Lane D — Escalate (only when authorised)

- **AWS IMDSv2** — `PUT /latest/api/token` (with TTL header) then `GET`
  with the `X-aws-ec2-metadata-token` header.
- **GCP / Azure** — require their metadata header
  (`Metadata-Flavor: Google` / `Metadata: true`).
- Retrieve instance credentials and demonstrate their (in-scope) reach.

## 6. Lane E — Internal pivot

Port-scan internal ranges, hit internal-only admin/health endpoints,
smuggle non-HTTP protocols where viable.

## 7. Proof & report

Capture the credential / internal response showing impact.
`bounty_scope_check`, then `report_hackerone` / `report_bugcrowd_csv`.
Use `cve_poc_lookup` for product-specific SSRF chains.
