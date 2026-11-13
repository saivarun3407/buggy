import { test } from "node:test";
import assert from "node:assert/strict";
import { isValidEngagementSlug, ENGAGEMENT_SLUG_RE } from "./engagement-slug";

// These payloads are exactly what the PATCH + approvals routes must reject so a
// rename can never make WORKSPACE/<name>/... escape WORKSPACE_PATH.
const TRAVERSAL_PAYLOADS = [
  "../../tmp/pwn",
  "..",
  "../etc",
  "/etc/passwd",
  "/absolute/path",
  "a/../../b",
  "foo/bar",
  "foo\\bar",
  ".hidden",
  "name with spaces",
  "UPPERCASE",
  "name_underscore",
  "-leading-hyphen",
  "trailing-hyphen-",
  "ab", // too short (regex requires >= 3 chars)
  "a".repeat(65), // too long (regex caps at 64 chars)
  "name.with.dots",
  "",
];

const VALID_SLUGS = [
  "engagement-1",
  "abc",
  "a1b2c3",
  "my-long-engagement-name-2026",
  "a".repeat(64),
];

test("isValidEngagementSlug rejects path-traversal and malformed names", () => {
  for (const payload of TRAVERSAL_PAYLOADS) {
    assert.equal(isValidEngagementSlug(payload), false, `expected reject: ${JSON.stringify(payload)}`);
  }
});

test("isValidEngagementSlug accepts well-formed workspace slugs", () => {
  for (const slug of VALID_SLUGS) {
    assert.equal(isValidEngagementSlug(slug), true, `expected accept: ${slug}`);
  }
});

test("isValidEngagementSlug rejects non-string input", () => {
  for (const v of [undefined, null, 123, {}, [], true]) {
    assert.equal(isValidEngagementSlug(v as unknown), false);
  }
});

test("ENGAGEMENT_SLUG_RE is anchored and matches the create-route policy", () => {
  // Must be fully anchored — a traversal payload embedding a valid slug must not
  // pass via a partial match.
  assert.equal(ENGAGEMENT_SLUG_RE.test("good-slug\n../evil"), false);
  assert.equal(ENGAGEMENT_SLUG_RE.source, "^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$");
});
