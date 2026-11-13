import { useMemo } from "react";
import type { AgentEvent, SubAgentSession } from "../types.js";
import { deriveSubAgentSessions } from "@buggy/streaming";

/**
 * Derive structured sub-agent sessions from the flat event stream.
 *
 * Delegates to the shared deriveSubAgentSessions() function from
 * @buggy/streaming, wrapped in useMemo for React performance.
 */
export function useSubAgentSessions(events: AgentEvent[]): SubAgentSession[] {
  return useMemo(() => deriveSubAgentSessions(events), [events]);
}
