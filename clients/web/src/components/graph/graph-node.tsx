"use client";

import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  Monitor,
  Server,
  Bug,
  ShieldAlert,
  User,
  Key,
  FileWarning,
  Route,
  Shield,
  CheckCircle,
  Crosshair,
  Globe,
  Lock,
  Code,
  Cpu,
} from "lucide-react";

const nodeConfig: Record<
  string,
  { color: string; bg: string; icon: typeof Monitor }
> = {
  Host: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/30", icon: Monitor },
  Service: { color: "text-green-400", bg: "bg-green-500/10 border-green-500/30", icon: Server },
  Vulnerability: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/30", icon: Bug },
  CVE: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30", icon: ShieldAlert },
  User: { color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/30", icon: User },
  Credential: { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30", icon: Key },
  Finding: { color: "text-pink-400", bg: "bg-pink-500/10 border-pink-500/30", icon: FileWarning },
  AttackPath: { color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/30", icon: Route },
  // Defense / Offensive Vaccine nodes
  DefenseAction: { color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30", icon: Shield },
  DetectionFired: { color: "text-teal-400", bg: "bg-teal-500/10 border-teal-500/30", icon: Crosshair },
  Verification: { color: "text-lime-400", bg: "bg-lime-500/10 border-lime-500/30", icon: CheckCircle },
  // Additional infrastructure nodes
  Domain: { color: "text-sky-400", bg: "bg-sky-500/10 border-sky-500/30", icon: Globe },
  Secret: { color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/30", icon: Lock },
  SourceFile: { color: "text-slate-400", bg: "bg-slate-500/10 border-slate-500/30", icon: Code },
  Technology: { color: "text-indigo-400", bg: "bg-indigo-500/10 border-indigo-500/30", icon: Cpu },
};

const defaultConfig = {
  color: "text-zinc-400",
  bg: "bg-zinc-500/10 border-zinc-500/30",
  icon: Monitor,
};

export function GraphNode({ data }: NodeProps) {
  const config = nodeConfig[data.nodeType as string] ?? defaultConfig;
  const Icon = config.icon;

  return (
    <div
      className={`rounded-lg border px-3 py-2 shadow-md ${config.bg}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-border" />
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 shrink-0 ${config.color}`} />
        <div className="min-w-0">
          <div className="truncate text-xs font-medium text-foreground max-w-[120px]">
            {String(data.label ?? "")}
          </div>
          <div className="text-[10px] text-muted-foreground">
            {String(data.nodeType ?? "")}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-border" />
    </div>
  );
}
