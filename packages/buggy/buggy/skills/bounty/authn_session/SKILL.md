---
name: authn-session-takeover
description: Hunt authentication, federation, and session bugs that lead to account takeover — JWT attacks (alg confusion, none, kid injection), OAuth/OIDC/SAML flaws, password-reset and MFA bypass, and session-lifecycle issues. Chain primitives to a proven takeover.
metadata:
  subdomain: web-exploitation
  when_to_use: "authentication authorization session account takeover ato jwt alg confusion none kid oauth oidc saml sso password reset mfa bypass session fixation cookie federation"
  mitre_attack: T1078, T1539, T1606, T1110
---

# Authentication / Session Takeover Playbook

Account takeover (ATO) is the highest-payout class in most programs, and
it lives in the seams between identity components. The deliverable is a
proven takeover — you control the victim's session/account — not a
theoretical weakness.

## 1. Map the auth surface

Login, registration, password reset, MFA enrolment/verification,
SSO/federation, token issuance/refresh, logout. For each, state the
invariant it must hold (e.g. "reset token is per-account, single-use,
expiring").

## 2. Lane A — JWT / token attacks

- Decode first. Then test:
  - **alg confusion** — RS256→HS256 signing with the public key as the
    HMAC secret.
  - **`alg: none`** / missing signature verification.
  - **`kid` injection / path traversal** (point `kid` at a known file or
    SQL-inject it).
  - **weak HMAC secret** — crack with `hashcat`/`jwt_tool`.
  - claims trusted downstream (`role`, `admin`, `sub`) — tamper them.
  - expiry / replay handling.

## 3. Lane B — OAuth / OIDC / SAML

- `redirect_uri` validation gaps (open redirect → code/token theft).
- missing/replayable `state` (CSRF on the callback).
- authorization-code leakage/replay, PKCE downgrade, audience confusion.
- SAML: signature stripping, XML signature wrapping (XSW).

## 4. Lane C — Reset / registration / enumeration

- Reset-token entropy, reuse, no expiry; host-header poisoning of the
  reset link → token exfil.
- Pre-account-takeover via unverified email; username enumeration via
  timing/response diffs.

## 5. Lane D — Session lifecycle

- Session fixation; missing invalidation on logout / password change;
  concurrent sessions; cookie flags (HttpOnly / Secure / SameSite).

## 6. Proof & report

Demonstrate ATO end-to-end with captured requests showing the second
account compromised. `bounty_scope_check`, then `report_hackerone` /
`report_bugcrowd_csv`. `h1_search` is invaluable for disclosed ATO
chains.
