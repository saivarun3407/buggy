# BloodHound 5.x → KGStore Mapping (RFC)

**Date:** 2026-06-04
**Status:** Draft — review required before implementation
**Scope:** AD_TOOLS (`packages/buggy/buggy/tools/ad/`) migration from the legacy `_state` shim + in-memory `KnowledgeGraph` to direct `KGStore.record_observations` calls.
**Out of scope:** Slither / smart-contract auditor migration (see companion RFC `2026-06-04-slither-kgstore-mapping.md`).

---

## 1. Why this RFC exists

After PR #549 ("retire legacy Neo4jStore, route _state through KGStore") the AD operator's BloodHound ingestion still works — but through the legacy `_state` compat shim. The shim translates the old `KnowledgeGraph` `_load → mutate → _save` pattern into `KGStore.record_observations` calls behind the scenes, so the tool code in `tools/ad/bloodhound.py` did not need to change. That gets us off the deleted `Neo4jStore` class, but it leaves four real gaps:

1. **Schema fidelity** — Buggy's `NodeKind` enum has 6 AD-relevant kinds (`USER`, `HOST`, `GROUP`, `DOMAIN`, plus `GROUP` reused for GPO/OU). BHCE 5.x emits **13 distinct node kinds** plus `LocalGroup` (User, Computer, Group, Domain, GPO, OU, Container, CertTemplate, EnterpriseCA, RootCA, AIACA, NTAuthStore, IssuancePolicy). Collapsing them to 6 loses the type information the BloodHound chain analysis depends on.
2. **Trust modelling** — BHCE 5.x replaced the single `TrustedBy` edge with **4 distinct edges** based on `TrustType` + `IsTransitive`: `SameForestTrust`, `CrossForestTrust`, `AbuseTGTDelegation`, `SpoofSIDHistory`. The current Buggy mapping collapses all of them to `EdgeKind.ENABLES`. Path planners cannot distinguish a benign parent-child trust from an exploitable cross-forest trust.
3. **Implicit edges not synthesised** — BloodHound's `PrimaryGroupSID` is a property on User/Computer, not a separate edge. SharpHound expects ingest to synthesise the corresponding `MEMBER_OF` edge. Buggy's ingest currently skips this, so primary-group membership is invisible to the path planner.
4. **Post-process edges absent** — `Owns`, `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, ADCS `ESC1/3/4/6a/6b/9a/9b/10a/10b/13`, `GoldenCert`, `SyncLAPSPassword`, `DCSync`, `CoerceAndRelayNTLMTo*`, `CoerceToTGT`, `HasTrustKeys`, `SyncedToEntraUser` / `SyncedToADUser` are all **server-computed** in BHCE — raw collector data does not contain them. Buggy imports the raw graph only, so none of these edges exist. The AD operator is one strand removed from being able to reason about ADCS or coercion paths.

This RFC scopes what a faithful BloodHound → KGStore mapping needs and proposes a phased migration that preserves the ability to land each piece in a reviewable PR.

---

## 2. BloodHound 5.x JSON ground truth

Sources (verified 2026-06-04):

- `packages/go/ein/incoming_models.go` — SharpHound JSON → Go struct mapping (full schema)
- `packages/go/ein/ad.go` — ACE → Edge translation + post-processing rules (~51 KB)
- `packages/go/graphschema/ad/ad.go` — Node kind constants (13 AD + LocalGroup)
- `schemas/valid_edges.json` — all valid `(src, dst, edge kind)` triples and their raw vs post classification
- `bloodhound.specterops.io/integrations/bloodhound-api/json-formats` — JSON envelope reference

### 2.1 Envelope

Every file in a SharpHound ZIP is one of seven fixed `meta.type` values: `users`, `computers`, `groups`, `domains`, `gpos`, `ous`, `containers`. ADCS data is **not** a separate file — it is embedded inside `domains.json` / `users.json` / `computers.json` and the BHCE server splits it into `CertTemplate` / `EnterpriseCA` / `RootCA` / `AIACA` / `NTAuthStore` / `IssuancePolicy` kinds during ingest.

```json
{
  "data": [ ... ],
  "meta": {
    "methods": <int bitmask>,
    "type": "<users|...|containers>",
    "count": <int>,
    "version": 5
  }
}
```

- `version = 5` on BHCE main; collectors that still emit version `4` use the legacy schema (no ADCS, no Trust split) and need their own migration path.
- `meta.methods` is a bitmask (`Group=1`, `LocalAdmin=2`, `Session=4`, `ACL=32`, `Container=128`, `GPOLocalGroup=256`, `DCOnly=8192`, etc.) — useful provenance for "this ingest did not include sessions" debugging.

### 2.2 Node identifier rules

| BHCE kind | `ObjectIdentifier` form | Globally unique? |
|---|---|---|
| User, Computer, Group, Domain | SID | Within forest only — well-known SIDs (`S-1-5-32-544`, etc.) repeat across forests; SharpHound prefixes them with the NetBIOS name |
| GPO, OU, Container, CertTemplate, EnterpriseCA, RootCA, AIACA, NTAuthStore, IssuancePolicy | GUID | Globally unique |
| LocalGroup | `<computerSID>-<RID>` or `<computerSID>__<groupname>` | Synthesised — engagement scope is enough |

KGStore's `(key, engagement)` composite is the right model: each ObjectIdentifier becomes the `key`, the engagement label scopes it, and well-known SID collisions across forests stay separated.

### 2.3 The mapping table (provisional)

| BloodHound JSON path | KGStore `kind` | `key` rule | Core props |
|---|---|---|---|
| `users[].ObjectIdentifier` | `ADUser` | `f"aduser::{sid.upper()}"` | `name, domain, domainsid, distinguishedname, enabled, admincount, dontreqpreauth, hasspn, sensitive, trustedfordelegation, unconstraineddelegation, passwordnotreqd, pwdlastset, lastlogon, sidhistory, description` |
| `computers[].ObjectIdentifier` | `ADComputer` | `f"adcomputer::{sid.upper()}"` | `name, samaccountname, domain, domainsid, operatingsystem, enabled, unconstraineddelegation, trustedtoauth, isdc, haslaps, lastlogontimestamp, sidhistory` |
| `groups[].ObjectIdentifier` | `ADGroup` | `f"adgroup::{sid.upper()}"` | `name, domain, domainsid, admincount, description, samaccountname` |
| `domains[].ObjectIdentifier` | `ADDomain` | `f"addomain::{sid.upper()}"` | `name, functionallevel, distinguishedname` |
| `gpos[].ObjectIdentifier` | `ADGPO` | `f"adgpo::{guid.upper()}"` | `name, gpcpath, description` |
| `ous[].ObjectIdentifier` | `ADOU` | `f"adou::{guid.upper()}"` | `name, blocksinheritance, description` |
| `containers[].ObjectIdentifier` | `ADContainer` | `f"adcontainer::{guid.upper()}"` | `name, distinguishedname` |
| `domains[].` (embed) `CertTemplate` | `ADCertTemplate` | `f"certtemplate::{guid.upper()}"` | `enrolleesuppliessubject, schemaversion, authenticationenabled, requiresmanagerapproval, nosecurityextension, enrollmentflag, effectiveekus, ekus, certificatenameflag` |
| (embed) `EnterpriseCA` | `ADEnterpriseCA` | `f"enterpriseca::{guid.upper()}"` | `caname, dnshostname, isuserspecifiessanenabled, hasenrollmentagentrestrictions, hashttpenrollmentendpoints` |
| (embed) `RootCA` | `ADRootCA` | `f"rootca::{guid.upper()}"` | `domain, domainsid` |
| (embed) `AIACA` | `ADAIACA` | `f"aiaca::{guid.upper()}"` | `domain` |
| (embed) `NTAuthStore` | `ADNTAuthStore` | `f"ntauthstore::{guid.upper()}"` | `domain, certthumbprints` |
| (embed) `IssuancePolicy` | `ADIssuancePolicy` | `f"issuancepolicy::{guid.upper()}"` | `displayname, certtemplateoid` |
| `computers[].LocalGroups[]` | `ADLocalGroup` | `f"adlocalgroup::{ObjectIdentifier.upper()}"` | `name, ComputerObjectIdentifier` |

### 2.4 Edges (`schemas/valid_edges.json`)

| BloodHound source | Edge kind | Direction | Notes |
|---|---|---|---|
| `groups[].Members[]` | `MEMBER_OF` | member → group | Most common edge; transitive computed separately |
| `users[].PrimaryGroupSID` (prop) | `MEMBER_OF` | user → group | **Trap**: NOT an edge in JSON; must be synthesised |
| `computers[].PrimaryGroupSID` (prop) | `MEMBER_OF` | computer → group | Same trap |
| `users[].AllowedToDelegate[]` | `ALLOWED_TO_DELEGATE` | user → computer | Constrained delegation |
| `computers[].AllowedToDelegate[]` | `ALLOWED_TO_DELEGATE` | computer → computer | |
| `computers[].AllowedToAct[]` | `ALLOWED_TO_ACT` | principal → computer | RBCD |
| `users[].SPNTargets[]` | `WriteSPN` / `SPNTarget` (post) | user → computer | Targeted Kerberoasting; `{ComputerSID, Port, Service}` |
| `*.HasSIDHistory[]` | `HAS_SID_HISTORY` | principal → principal | Cross-domain |
| `computers[].Sessions.Results[]` | `HAS_SESSION` | **computer → user** | Trap — direction is backwards from what most diagrams imply; preserve `logon_type` prop |
| `computers[].PrivilegedSessions.Results[]` | `HAS_SESSION` (privileged=true) | computer → user | |
| `computers[].RegistrySessions.Results[]` | `HAS_SESSION` (source=registry) | computer → user | |
| `computers[].LocalGroups[].Results[]` | `MEMBER_OF_LOCAL_GROUP` | principal → localgroup | Post-process → `AdminTo` / `CanRDP` / `ExecuteDCOM` / `CanPSRemote` by RID |
| `computers[].UserRights[]` (`SeRemoteInteractiveLogonRight`) | `RemoteInteractiveLogonRight` | principal → computer | Post → `CanRDP` |
| `computers[].DumpSMSAPassword[]` | `DumpSMSAPassword` | computer → user | sMSA |
| ALL `*.Aces[]` | edge kind = `RightName` | principal → target | See list below; **trap**: `Owns` and `WriteOwner` are raw `OwnsLimitedRights` / `WriteOwnerLimitedRights` — server post-processes to `Owns` |
| `*.ContainedBy` | `CONTAINS` (reversed) | parent → child | Child carries parent pointer; flip during ingest |
| `domains[].ChildObjects[]` / `ous[].ChildObjects[]` / `containers[].ChildObjects[]` | `CONTAINS` | parent → child | Forward direction |
| `domains[].Links[]` / `ous[].Links[]` | `GP_LINK` | GPO → domain/OU | `Guid` is normalised to GPO objectid; props `{enforced}` |
| `domains[].Trusts[]` | `SameForestTrust` / `CrossForestTrust` / `AbuseTGTDelegation` / `SpoofSIDHistory` | source domain → target domain | **Trap**: 4-way split based on `TrustType` (`ParentChild` / `CrossLink` / `Forest` / `External`) + `IsTransitive` |
| `*.GPOChanges.LocalAdmins[]` | post → `AdminTo` / `CanRDP` / `ExecuteDCOM` / `CanPSRemote` | principal → affected computer | Cross product with `AffectedComputers[]` |
| `EnterpriseCA.EnabledCertTemplates[]` | `PUBLISHED_TO` | EnterpriseCA → CertTemplate | |
| `EnterpriseCA.HostingComputer` | `HOSTS_CA_SERVICE` | computer → EnterpriseCA | |
| `IssuancePolicy.GroupLink` | `OID_GROUP_LINK` | IssuancePolicy → group | ESC13 core |
| `NTAuthStore.certthumbprints` ↔ EnterpriseCA cert chain | `TRUSTED_FOR_NTAUTH` | EnterpriseCA → NTAuthStore | Post-process |
| RootCA/AIACA chain | `ROOT_CA_FOR` / `ISSUED_SIGNED_BY` | RootCA → Domain, EnterpriseCA → RootCA | Post-process |

### 2.5 ACE right names (Aces[].RightName)

Raw values that map 1:1 to edge kind (no post-processing): `GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `AddMember`, `AddSelf`, `AllExtendedRights`, `ForceChangePassword`, `ReadGMSAPassword`, `ReadLAPSPassword`, `AddKeyCredentialLink`, `WriteAccountRestrictions`, `WriteSPN`, `WriteGPLink`, `ManageCA`, `ManageCertificates`, `GetChanges`, `GetChangesAll`.

Post-processed (raw → server-computed promotion): `OwnsLimitedRights` → `Owns`, `WriteOwnerLimitedRights` → `WriteOwner`.

### 2.6 ADCS post-process edges (`schemas/valid_edges.json`, post category)

`ADCSESC1`, `ADCSESC3`, `ADCSESC4`, `ADCSESC6a`, `ADCSESC6b`, `ADCSESC9a`, `ADCSESC9b`, `ADCSESC10a`, `ADCSESC10b`, `ADCSESC13`, `GoldenCert`, `SyncLAPSPassword`, `DCSync`, `Owns`, `AdminTo`, `CanRDP`, `CanPSRemote`, `ExecuteDCOM`, `CoerceAndRelayNTLMToADCS` / `LDAP` / `LDAPS` / `SMB`, `CoerceToTGT`, `HasTrustKeys`, `SyncedToEntraUser`, `SyncedToADUser`.

**As of BHCE main 2026-06**, `valid_edges.json` does not include `ESC2`, `ESC5`, `ESC7`, `ESC8`, `ESC11`, `ESC12`, `ESC14`, `ESC15`, `ESC16` — the community runs these through Certipy. KGStore should reserve placeholder kinds (`ADCS_ESC2`, etc.) so the data path is ready when collectors catch up.

### 2.7 Traps (must handle in ingest)

1. **`PrimaryGroupSID` is a prop, not an edge.** Synthesise `MEMBER_OF` from User/Computer to the corresponding Group during ingest.
2. **`Sessions.Results[]` direction is computer → user.** Reasoning about "user X logged in on host Y" requires reverse traversal.
3. **`ContainedBy` is child-held parent pointer.** Flip during ingest so canonical edges are `parent CONTAINS child`.
4. **`Aces[].Owns` is post-processed from `OwnsLimitedRights`.** Preserve both raw + post if path analysis is to match BHCE behaviour.
5. **`Trusts[]` is NOT a single `TrustedBy` edge.** Branch on `TrustType` + `IsTransitive` into 4 distinct edges.
6. **`GPOChanges` is GPTTmpl.inf parsing output.** Post-process to `AdminTo` / `CanRDP` / `ExecuteDCOM` / `CanPSRemote` via cross product with `AffectedComputers[]`.
7. **`LocalGroups[].ObjectIdentifier` follows `<computerSID>-<RID>`.** Built-in Administrators end in `-500`.
8. **Well-known SIDs collide across domains.** SharpHound prefixes with NetBIOS at collection time; KGStore composite unique handles it via engagement scope.
9. **`InheritanceHash` per ACE** — ContainedBy inheritance reasoning. Drop it and BHCE 5.x inheritance-aware path analysis breaks.
10. **`meta.methods` bitmask** — preserve as ingest provenance for "partial collection" debugging.
11. **`IsACLProtected` = true** — propagation must stop at that object; parent ACEs do NOT inherit through.
12. **`IsDeleted`** — tombstoned. Decide soft-delete vs hard-skip per engagement policy.
13. **`meta.version < 5`** — legacy schema without ADCS / Trust split; needs its own ingest path or rejection.

---

## 3. Architecture decision: how to represent BloodHound nodes in KGStore

This is the load-bearing decision the implementation depends on. Two options.

### Option A — Add dedicated BloodHound `NodeKind` values

`NodeKind` enum gains 13 new values (`AD_USER = "ADUser"`, `AD_COMPUTER`, `AD_GROUP`, `AD_DOMAIN`, `AD_GPO`, `AD_OU`, `AD_CONTAINER`, `AD_CERT_TEMPLATE`, `AD_ENTERPRISE_CA`, `AD_ROOT_CA`, `AD_AIA_CA`, `AD_NT_AUTH_STORE`, `AD_ISSUANCE_POLICY`) + `AD_LOCAL_GROUP`.

**Pros**
- Faithful to BHCE 5.x schema — Neo4j labels match what BloodHound documentation, queries, and Cypher cheatsheets expect.
- Path analysis can filter precisely: `MATCH (u:ADUser)-[:MEMBER_OF*]->(:ADGroup {admincount: 1})` etc.
- The existing `EdgeKind.MEMBER_OF` / `ADMIN_TO` / `OWNS` etc. coexist naturally; no risk of cross-domain contamination.
- ADCS modelling is honest: `:ADCertTemplate` is a real Neo4j label, not an `:Entrypoint` overload.

**Cons**
- `buggy-core` enum churn. Every existing `MATCH (u:User)` query in `chain.py` / `health.py` / agents needs to also match `:ADUser`, or run a one-shot migration to relabel old data.
- V001 / V002 migration in `KGStore` must add composite-unique constraints + indexes for each new label (~13 new constraints).
- More NodeKind values means more places in agent prompts / skills that may need to be updated to mention them.

### Option B — Reuse `NodeKind.USER` / `HOST` / `GROUP` with a `bh_type` prop

Keep `NodeKind` unchanged. Differentiate AD-origin nodes via a `bh_type` property (`bh_type="User"` / `"Computer"` / etc.).

**Pros**
- Zero `buggy-core` change; the 549 cleanup stays clean.
- `chain.py` Cypher works unchanged for AD/non-AD queries.
- Existing tests untouched.

**Cons**
- BHCE Cypher cheatsheets and queries don't apply — every analyst recipe has to be rewritten as `WHERE n.bh_type = "Computer"` instead of `MATCH (c:Computer)`.
- ADCS modelling collapses — `CertTemplate`, `EnterpriseCA`, `IssuancePolicy` etc. would need to overload existing kinds (e.g. CertTemplate as `:Finding` with `bh_type="CertTemplate"`), which is semantically wrong.
- Indexing is weaker (filter on a string prop, not a label).
- Future BloodHound feature parity (e.g. running BloodHound's own Neo4j data import into the same graph) is impossible because labels don't match.

### Recommendation

**Option A** — the cost is one-time enum churn + a V003 migration; the benefit is faithful BHCE 5.x modelling and the ability to use the well-understood BloodHound Cypher patterns directly. Option B saves work today but compounds debt every time a new ADCS / kerberos / coercion edge lands upstream.

---

## 4. Phased migration plan (after this RFC is approved)

Each step lands as a separate PR. Steps later than 4.1 depend on earlier ones being merged.

### 4.1 `NodeKind` / `EdgeKind` extension

- `buggy-core/types/kg.py`: add 13 AD node kinds + `AD_LOCAL_GROUP`.
- Add edge kinds: 4-way Trust (`SAME_FOREST_TRUST` / `CROSS_FOREST_TRUST` / `ABUSE_TGT_DELEGATION` / `SPOOF_SID_HISTORY`), `ALLOWED_TO_DELEGATE`, `ALLOWED_TO_ACT`, `HAS_SID_HISTORY`, `GP_LINK`, `PUBLISHED_TO`, `HOSTS_CA_SERVICE`, `OID_GROUP_LINK`, `ROOT_CA_FOR`, `ISSUED_SIGNED_BY`, `TRUSTED_FOR_NTAUTH`, `ADCS_ESC1` … `ADCS_ESC13` (placeholders for community-collector parity), `GOLDEN_CERT`, `SYNC_LAPS_PASSWORD`, `DCSYNC`, `COERCE_AND_RELAY_NTLM_TO_ADCS` / `LDAP` / `LDAPS` / `SMB`, `COERCE_TO_TGT`, `HAS_TRUST_KEYS`, `SYNCED_TO_ENTRA_USER`, `SYNCED_TO_AD_USER`, `DUMP_SMSA_PASSWORD`, `MEMBER_OF_LOCAL_GROUP`, `WRITE_SPN`, `READ_LAPS_PASSWORD`, `READ_GMSA_PASSWORD`, `ADD_KEY_CREDENTIAL_LINK`, `ALL_EXTENDED_RIGHTS`, `FORCE_CHANGE_PASSWORD`, `MANAGE_CA`, `MANAGE_CERTIFICATES`, `GET_CHANGES`, `GET_CHANGES_ALL`, `OWNS_LIMITED_RIGHTS`, `WRITE_OWNER_LIMITED_RIGHTS`, `WRITE_DACL`, `WRITE_OWNER`.
- KGStore `V003__bloodhound_schema.cypher` migration: composite `(key, engagement) UNIQUE` constraint per new label + label-scoped indexes for hot props (`Aces.RightName`, `Trusts.TrustType`, etc.).

### 4.2 BloodHound ingest core

- Rewrite `tools/ad/bloodhound.py` to emit observations directly via `KGStore.record_observations` — no `KnowledgeGraph` round-trip.
- Implement the trap handlers from §2.7: `PrimaryGroupSID` edge synth, `Sessions` direction, `ContainedBy` flip, Trust 4-way split, ACE Owns / WriteOwner raw + post promotion, `IsACLProtected` propagation stop, `InheritanceHash` preservation, `meta.methods` provenance.

### 4.3 ADCS post-process edges

- A new `tools/ad/adcs_post.py` module: traverses the ingested raw graph, computes the BHCE-server-equivalent ESC1/3/4/6a/6b/9a/9b/10a/10b/13 + GoldenCert + SyncLAPSPassword + DCSync edges.
- Triggered after `bh_ingest_zip` completes for the engagement.

### 4.4 LocalAdmin / GPO post-process

- `tools/ad/local_admin_post.py`: cross-product `GPOChanges.LocalAdmins[]` with `AffectedComputers[]` → `AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM`.
- `LocalGroups[].Results[]` → `AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM` based on built-in RID (`-500` = Admins, `-555` = RDP, etc.).

### 4.5 Test migration + live validation

- Migrate `tests/unit/ad/test_bloodhound*.py` to the new observation API.
- Add live BHCE 5.x sample data fixture (small redacted export) + golden-output assertions on the resulting KGStore observations.
- `make dogfood` end-to-end: ingest sample BHCE export → analyst queries reachability → matches BHCE web UI.

### 4.6 Shim removal for AD

- After 4.1 – 4.5 land, `tools/ad/tools.py` no longer imports from `tools.research._state`.
- The `_state` shim stays in place for Contract / Research tools until their own migrations finish.

---

## 5. Open questions

- **Should the legacy `KnowledgeGraph` Pydantic model be deprecated in lockstep with this work, or kept as a query-time materialisation helper?** The renderers in `tools/reporting/` still use it; PR #548 routes them through `kg_adapter.load_engagement_graph`. The renderers themselves are independent of the BloodHound migration but share the model.
- **Migration of existing engagement data with old-style labels (`:User` / `:Computer` / `:Group`)?** Either a one-shot Cypher relabelling job (`MATCH (n:User) WHERE n.bh_type = "User" SET n:ADUser REMOVE n:User`) or accept that old engagements stay on old labels. Recommend the latter — engagement data is short-lived in practice.
- **NodeKind values that overlap with non-AD use** — `Domain`, `Container`, `Group` already exist in the general attack-graph schema. Decision: AD-prefixed kinds are additive; the existing generic kinds keep their non-AD semantics.
- **Backwards compat for the 6-kind ingest output already in production engagements** — if any user has live engagement data ingested by the current `bloodhound.py`, do we offer a relabel script? Recommend: documented one-liner Cypher, not a runtime auto-migration.

---

## 6. Sources

- [BloodHound JSON Formats — SpecterOps docs](https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats)
- [SpecterOps/BloodHound · packages/go/ein/incoming_models.go](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/ein/incoming_models.go)
- [SpecterOps/BloodHound · schemas/valid_edges.json](https://github.com/SpecterOps/BloodHound/blob/main/schemas/valid_edges.json)
- [SpecterOps/BloodHound · packages/go/graphschema/ad/ad.go](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/graphschema/ad/ad.go)
- [SpecterOps/SharpHound (C# Collector)](https://github.com/SpecterOps/SharpHound)
- [ADCSESC1 edge reference](https://bloodhound.specterops.io/resources/edges/adcs-esc1)
- [Data Collection — DeepWiki BloodHound 5.1](https://deepwiki.com/SpecterOps/BloodHound/5.1-data-collection)
