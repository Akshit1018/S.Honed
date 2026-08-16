import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/report";

const tone: Record<Severity, string> = {
  critical: "text-critical border-critical/30",
  high: "text-high border-high/30",
  medium: "text-medium border-medium/30",
  low: "text-low border-low/30",
  info: "text-info border-line",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center rounded-sm border px-2 font-mono text-[0.6875rem] uppercase tracking-[0.12em]",
        tone[severity],
      )}
    >
      {severity}
    </span>
  );
}

export function QuietBadge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center rounded-sm border border-border px-2 font-mono text-[0.6875rem] uppercase tracking-[0.12em] text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}
