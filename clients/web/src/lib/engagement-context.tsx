"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { SubagentCustomEvent } from "@buggy/streaming";

interface EngagementContextValue {
  engagementId: string;
  engagementSlug: string;
  agentId: "soundwave" | "buggy";
  threadId: string | null;
  setThreadId: (id: string) => void;
  events: SubagentCustomEvent[];
  isRunning: boolean;
  activeRunId: string | null;
}

const EngagementContext = createContext<EngagementContextValue | null>(null);

export function useEngagementContext(): EngagementContextValue {
  const ctx = useContext(EngagementContext);
  if (!ctx) throw new Error("useEngagementContext must be used within EngagementProvider");
  return ctx;
}

interface EngagementProviderProps {
  children: ReactNode;
  engagementId: string;
  engagementSlug: string;
  agentId: "soundwave" | "buggy";
  threadId: string | null;
  setThreadId: (id: string) => void;
  events: SubagentCustomEvent[];
  isRunning: boolean;
  activeRunId: string | null;
}

export function EngagementProvider({
  children,
  engagementId,
  engagementSlug,
  agentId,
  threadId,
  setThreadId,
  events,
  isRunning,
  activeRunId,
}: EngagementProviderProps) {
  return (
    <EngagementContext.Provider
      value={{
        engagementId,
        engagementSlug,
        agentId,
        threadId,
        setThreadId,
        events,
        isRunning,
        activeRunId,
      }}
    >
      {children}
    </EngagementContext.Provider>
  );
}
