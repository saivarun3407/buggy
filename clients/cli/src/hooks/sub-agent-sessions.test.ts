import { describe, expect, it } from "vitest";

import { deriveSubAgentSessions, type StreamEvent } from "@buggy/streaming";

let seq = 0;
/** Build a minimal StreamEvent with sensible id/timestamp defaults. */
function ev(over: Partial<StreamEvent> & { type: string }): StreamEvent {
  seq += 1;
  return { id: `e${seq}`, timestamp: seq, ...over };
}

describe("deriveSubAgentSessions", () => {
  it("groups a start/end pair into one completed session", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "recon", content: "scan target" }),
      ev({ type: "subagent_end", subagent: "recon", status: "success" }),
    ]);
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({ agent: "recon", description: "scan target", status: "completed" });
    expect(sessions[0].endEventId).toBeDefined();
    expect(sessions[0].endTime).toBeDefined();
  });

  it("marks errored when subagent_end carries status='error' (CLI-normalized shape)", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "exploit" }),
      ev({ type: "subagent_end", subagent: "exploit", status: "error" }),
    ]);
    expect(sessions[0].status).toBe("error");
  });

  it("marks errored when subagent_end carries error=true (raw backend shape)", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "exploit" }),
      ev({ type: "subagent_end", subagent: "exploit", error: true }),
    ]);
    expect(sessions[0].status).toBe("error");
  });

  it("leaves a session running until its subagent_end arrives", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "recon" }),
      ev({ type: "tool_result", subagent: "recon" }),
    ]);
    expect(sessions[0].status).toBe("running");
    expect(sessions[0].endEventId).toBeUndefined();
    expect(sessions[0].endTime).toBeUndefined();
  });

  it("counts only tool_result and bash_result events between start and end", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "recon" }),
      ev({ type: "tool_result", subagent: "recon" }),
      ev({ type: "bash_result", subagent: "recon" }),
      ev({ type: "ai_message", subagent: "recon" }), // not a tool result → not counted
      ev({ type: "subagent_end", subagent: "recon" }),
    ]);
    expect(sessions[0].toolCount).toBe(2);
    expect(sessions[0].eventIds).toHaveLength(5);
  });

  it("ignores a subagent_end with no matching open session", () => {
    const sessions = deriveSubAgentSessions([ev({ type: "subagent_end", subagent: "ghost" })]);
    expect(sessions).toHaveLength(0);
  });

  it("derives independent sessions for interleaved subagents", () => {
    const sessions = deriveSubAgentSessions([
      ev({ type: "subagent_start", subagent: "recon" }),
      ev({ type: "subagent_start", subagent: "exploit" }),
      ev({ type: "subagent_end", subagent: "exploit", error: true }),
      ev({ type: "subagent_end", subagent: "recon", status: "success" }),
    ]);
    expect(sessions).toHaveLength(2);
    const byAgent = Object.fromEntries(sessions.map((s) => [s.agent, s.status]));
    expect(byAgent).toEqual({ recon: "completed", exploit: "error" });
  });

  it("falls back to a default description when content is absent", () => {
    const sessions = deriveSubAgentSessions([ev({ type: "subagent_start", subagent: "recon" })]);
    expect(sessions[0].description).toBe("Starting recon");
  });
});
