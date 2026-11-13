// Engagement name → workspace-directory slug policy.
//
// An engagement `name` doubles as the on-disk workspace directory slug: routes
// build filesystem paths with `path.join(WORKSPACE, engagement.name, ...)`
// (timeline, findings, plan-docs, documents, export, opplan, graph, approvals).
// Any name that reaches a filesystem path therefore MUST satisfy this rule,
// otherwise values like "../../tmp/pwn" or absolute paths escape WORKSPACE_PATH
// (authenticated path traversal / arbitrary file read-write).
//
// This regex is the single source of truth shared with the engagement CREATE
// route (api/engagements/route.ts) and the Go launcher
// (clients/launcher/internal/engagement/picker.go): 3-64 chars, lowercase
// letters / digits with internal hyphens only, no leading/trailing hyphen, no
// path separators, no dot prefix.
export const ENGAGEMENT_SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;

export function isValidEngagementSlug(name: unknown): name is string {
  return typeof name === "string" && ENGAGEMENT_SLUG_RE.test(name);
}
