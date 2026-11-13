-- KG schema v003 — composite uniqueness for BloodHound 5.x AD kinds
-- and Slither (Solidity) element kinds.
--
-- New labels added by this migration are emitted by:
--   - ``tools/ad/bloodhound.py`` (AD_USER … AD_ISSUANCE_POLICY + AD_LOCAL_GROUP)
--     after the BloodHound ingest rewrite — see
--     ``docs/design/2026-06-04-bloodhound-kgstore-mapping.md``.
--   - ``tools/contracts/slither.py`` (Function / StateVar / Event /
--     CustomError / Enum / Struct / Pragma) after the Slither ingest
--     rewrite — see
--     ``docs/design/2026-06-04-slither-kgstore-mapping.md``.
--
-- Same ``(key, engagement)`` composite invariant as V001: same key in
-- two engagements is two nodes (multi-tenant); same key in the same
-- engagement is one node (idempotent MERGE for record_observations).

-- ── Active Directory (BloodHound 5.x) ────────────────────────────────

CREATE CONSTRAINT ad_user_key_engagement IF NOT EXISTS
  FOR (n:ADUser) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_computer_key_engagement IF NOT EXISTS
  FOR (n:ADComputer) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_group_key_engagement IF NOT EXISTS
  FOR (n:ADGroup) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_domain_key_engagement IF NOT EXISTS
  FOR (n:ADDomain) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_gpo_key_engagement IF NOT EXISTS
  FOR (n:ADGPO) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_ou_key_engagement IF NOT EXISTS
  FOR (n:ADOU) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_container_key_engagement IF NOT EXISTS
  FOR (n:ADContainer) REQUIRE (n.key, n.engagement) IS UNIQUE;

-- ADCS labels
CREATE CONSTRAINT ad_cert_template_key_engagement IF NOT EXISTS
  FOR (n:ADCertTemplate) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_enterprise_ca_key_engagement IF NOT EXISTS
  FOR (n:ADEnterpriseCA) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_root_ca_key_engagement IF NOT EXISTS
  FOR (n:ADRootCA) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_aia_ca_key_engagement IF NOT EXISTS
  FOR (n:ADAIACA) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_nt_auth_store_key_engagement IF NOT EXISTS
  FOR (n:ADNTAuthStore) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT ad_issuance_policy_key_engagement IF NOT EXISTS
  FOR (n:ADIssuancePolicy) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT ad_local_group_key_engagement IF NOT EXISTS
  FOR (n:ADLocalGroup) REQUIRE (n.key, n.engagement) IS UNIQUE;

-- ── Solidity (Slither --json) ────────────────────────────────────────
-- ``Contract`` and ``SourceFile`` already have constraints from V001;
-- this only adds the new element labels.

CREATE CONSTRAINT solidity_function_key_engagement IF NOT EXISTS
  FOR (n:Function) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_state_var_key_engagement IF NOT EXISTS
  FOR (n:StateVar) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_event_key_engagement IF NOT EXISTS
  FOR (n:Event) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_custom_error_key_engagement IF NOT EXISTS
  FOR (n:CustomError) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_enum_key_engagement IF NOT EXISTS
  FOR (n:Enum) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_struct_key_engagement IF NOT EXISTS
  FOR (n:Struct) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT solidity_pragma_key_engagement IF NOT EXISTS
  FOR (n:Pragma) REQUIRE (n.key, n.engagement) IS UNIQUE;
