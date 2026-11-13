import { Client } from "@langchain/langgraph-sdk";
import type { Command } from "./types.js";
import { getAssistantOverride } from "./assistantOverride.js";

function apiBase(): string {
  return process.env.BUGGY_API_URL || "http://localhost:2024";
}

const ping: Command = {
  name: "ping",
  description: "Ping the active orchestrator to verify connectivity and LLM routing",
  async execute(_args, ctx) {
    ctx.addSystemEvent("● Pinging orchestrator...");

    // 1. API Connection Check
    try {
      const res = await fetch(`${apiBase()}/ok`);
      if (!res.ok) {
        throw new Error(`API returned status ${res.status}`);
      }
    } catch (err) {
      ctx.addSystemEvent(
        `  ✖ LangGraph Platform API check failed: ${err instanceof Error ? err.message : String(err)}\n` +
        `    Is the Buggy stack up and running? (Try 'buggy start')`
      );
      return;
    }
    ctx.addSystemEvent("  ✔ LangGraph Platform API is healthy (HTTP 200)");

    // 2. Resolve Active Orchestrator
    const override = getAssistantOverride();
    const activeOrchestrator = override || "buggy";
    ctx.addSystemEvent(`  ✔ Active orchestrator: ${activeOrchestrator} ${override ? "(override)" : "(default)"}`);

    // 3. LLM Routing Check
    ctx.addSystemEvent("  ● Verifying LLM routing (sending lightweight probe)...");
    const client = new Client({ apiUrl: apiBase() });
    let tempThreadId: string | null = null;

    try {
      // Create temporary thread
      const thread = await client.threads.create();
      tempThreadId = thread.thread_id;

      // Start run stream with a short max_tokens check
      const stream = client.runs.stream(
        thread.thread_id,
        activeOrchestrator,
        {
          input: { messages: [{ role: "user", content: "Ping" }] },
          config: {
            configurable: {
              max_tokens: 5,
            }
          },
          streamMode: ["messages"],
        }
      );

      // We just need the first chunk (value, message, or update) to prove that
      // the orchestrator successfully resolved the LLM and started the run.
      let receivedChunk = false;
      for await (const chunk of stream) {
        receivedChunk = true;
        break; // Stop immediately upon receiving any event
      }

      if (receivedChunk) {
        ctx.addSystemEvent("  ✔ LLM routing check successful (orchestrator is responsive)");
      } else {
        throw new Error("Orchestrator run stream closed with no events");
      }
    } catch (err) {
      ctx.addSystemEvent(
        `  ✖ LLM routing check failed: ${err instanceof Error ? err.message : String(err)}\n` +
        `    Please check your API key configuration or provider status.`
      );
    } finally {
      // Clean up temporary thread
      if (tempThreadId) {
        try {
          await client.threads.delete(tempThreadId);
        } catch {
          // Ignore deletion failures during cleanup
        }
      }
    }
  },
};

export default ping;
