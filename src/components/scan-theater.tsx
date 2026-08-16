import { useEffect, useState } from "react";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

const STAGES = [
  { id: "resolve", who: "Scout", label: "Resolve the host" },
  { id: "fetch", who: "Scout", label: "Fetch the first document" },
  { id: "headers", who: "Auditor", label: "Read headers and cookies" },
  { id: "surface", who: "Auditor", label: "Probe well-known files" },
  { id: "dns", who: "Auditor", label: "Check mail DNS" },
  { id: "vendors", who: "Editor", label: "Inventory third-party hosts" },
  { id: "craft", who: "Editor", label: "Walk the document craft" },
  { id: "rank", who: "Smith", label: "Rank the playbook" },
] as const;

const LOG: { who: string; text: string }[] = [
  { who: "Scout", text: "Opening a public GET — no login, no write." },
  { who: "Scout", text: "Following redirects on 80 / 443 only." },
  { who: "Auditor", text: "HSTS, CSP, COOP, CORP, Set-Cookie flags." },
  { who: "Auditor", text: "security.txt, robots, sitemap, humans.txt." },
  { who: "Auditor", text: "SPF, DMARC, and CAA on the apex." },
  { who: "Editor", text: "Scripts, fonts, pixels — who else is on this page." },
  { who: "Editor", text: "Title, share card, headings, alt text." },
  { who: "Smith", text: "Scoring effort against impact." },
  { who: "Smith", text: "Drafting the header pack and the first patch." },
];

const AGENTS = [
  { name: "Scout", role: "Recon" },
  { name: "Auditor", role: "Security" },
  { name: "Editor", role: "Polish" },
  { name: "Smith", role: "Solutions" },
] as const;

export function ScanTheater({ target }: { target: string }) {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const id = window.setInterval(() => {
      setTick((n) => n + 1);
    }, 650);
    return () => window.clearInterval(id);
  }, []);

  const doneCount = Math.min(STAGES.length - 1, 1 + Math.floor(tick / 2));
  const running = Math.min(STAGES.length - 1, doneCount);
  const pct = Math.min(92, 8 + doneCount * 11 + (tick % 2) * 2);
  const logLines = LOG.slice(0, Math.min(LOG.length, 2 + Math.floor(tick / 2)));
  const activeWho = STAGES[running]?.who ?? "Scout";

  return (
    <section className="mx-auto w-full max-w-5xl px-5 py-12 sm:px-8 sm:py-16">
      <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">
        Inspection in progress
      </p>
      <h1 className="mt-3 font-display text-4xl tracking-tight text-fg sm:text-5xl">
        Reading the surface
      </h1>
      <p className="mt-4 max-w-2xl break-all text-muted">{target}</p>

      <div className="mt-8">
        <div className="flex items-baseline justify-between gap-4">
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
            Desk
          </p>
          <p className="font-mono text-sm tabular-nums text-muted">{pct}%</p>
        </div>
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-elevated">
          <div
            className="h-full bg-accent transition-[width] duration-500 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      <ul className="mt-10 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {AGENTS.map((agent) => (
          <li
            key={agent.name}
            className={cn(
              "rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)] transition-opacity duration-200",
              activeWho === agent.name ? "opacity-100" : "opacity-45",
            )}
          >
            <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              {agent.name}
            </p>
            <p className="mt-2 text-sm text-fg">{agent.role}</p>
          </li>
        ))}
      </ul>

      <div className="mt-10 grid gap-8 lg:grid-cols-12">
        <ol className="space-y-2 lg:col-span-6">
          {STAGES.map((stage, i) => {
            const state = i < doneCount ? "done" : i === running ? "run" : "wait";
            return (
              <li key={stage.id} className="flex items-center gap-3">
                <span
                  className={cn(
                    "flex size-5 shrink-0 items-center justify-center rounded-full",
                    state === "done" && "bg-low/20 text-low",
                    state === "run" && "bg-accent text-accent-fg",
                    state === "wait" && "bg-elevated text-subtle",
                  )}
                >
                  {state === "done" ? (
                    <Check className="size-3" strokeWidth={2.5} />
                  ) : (
                    <span className="font-mono text-[0.625rem]">{i + 1}</span>
                  )}
                </span>
                <span className={cn("text-sm", state === "wait" ? "text-subtle" : "text-fg")}>
                  {stage.label}
                </span>
              </li>
            );
          })}
        </ol>

        <ol className="space-y-2 font-mono text-sm lg:col-span-6">
          {logLines.map((line, i) => (
            <li key={`${line.who}-${i}`} className="flex gap-3">
              <span className="w-16 shrink-0 text-subtle">{line.who}</span>
              <span className="text-fg">{line.text}</span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
