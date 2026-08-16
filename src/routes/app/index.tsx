import { useEffect, useMemo, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { listScans } from "@/lib/scans";
import type { ScanSummary } from "@/lib/report";
import { Button } from "@/components/ui/button";
import { QuietBadge } from "@/components/ui/badge";
import { ScoreSpark } from "@/components/score-spark";

export const Route = createFileRoute("/app/")({ component: Work });

function Work() {
  const [rows, setRows] = useState<ScanSummary[] | null>(null);

  useEffect(() => {
    void listScans()
      .then(setRows)
      .catch(() => setRows([]));
  }, []);

  const posture = useMemo(() => {
    if (!rows || rows.length === 0) return null;
    const done = rows.filter((r) => r.status === "complete" && typeof r.score === "number");
    const latest = done[0];
    const avg =
      done.length > 0
        ? Math.round(done.reduce((s, r) => s + (r.score ?? 0), 0) / done.length)
        : 0;
    const openHigh = done.reduce((s, r) => s + r.criticalCount + r.highCount, 0);
    const history = [...done].reverse().map((r) => r.score ?? 0);
    return { latest, avg, openHigh, count: rows.length, history };
  }, [rows]);

  const byTarget = useMemo(() => {
    if (!rows) return [];
    const map = new Map<string, ScanSummary[]>();
    for (const row of rows) {
      const list = map.get(row.target) ?? [];
      list.push(row);
      map.set(row.target, list);
    }
    return [...map.entries()].map(([target, list]) => {
      const done = list.filter((r) => typeof r.score === "number");
      return {
        target,
        latest: list[0],
        history: [...done].reverse().map((r) => r.score ?? 0),
        high: done.reduce((s, r) => s + r.criticalCount + r.highCount, 0),
      };
    });
  }, [rows]);

  return (
    <main className="mx-auto w-full max-w-6xl px-5 py-12 sm:px-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">Workspace</p>
          <h1 className="mt-2 font-display text-4xl tracking-tight">Your briefs</h1>
        </div>
        <Button asChild>
          <Link to="/app/new">New brief</Link>
        </Button>
      </div>

      {posture && (
        <dl className="mt-10 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
            <dt className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              Latest
            </dt>
            <dd className="mt-2 font-display text-3xl tabular-nums tracking-tight">
              {posture.latest?.score ?? "—"}
              {posture.latest?.grade && (
                <span className="ml-2 text-lg text-muted">{posture.latest.grade}</span>
              )}
            </dd>
          </div>
          <div className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
            <dt className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              Average
            </dt>
            <dd className="mt-2 font-display text-3xl tabular-nums tracking-tight">{posture.avg}</dd>
          </div>
          <div className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
            <dt className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              Open high
            </dt>
            <dd className="mt-2 font-display text-3xl tabular-nums tracking-tight">{posture.openHigh}</dd>
          </div>
          <div className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
            <dt className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              Trend
            </dt>
            <dd className="mt-3">
              {posture.history.length > 1 ? (
                <ScoreSpark values={posture.history} />
              ) : (
                <span className="font-display text-3xl tabular-nums tracking-tight">{posture.count}</span>
              )}
            </dd>
          </div>
        </dl>
      )}

      {byTarget.length > 1 && (
        <section className="mt-12">
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">By surface</p>
          <ul className="mt-4 grid gap-2 sm:grid-cols-2">
            {byTarget.map((g) => (
              <li key={g.target}>
                <Link
                  to="/app/scans/$scanId"
                  params={{ scanId: g.latest.id }}
                  className="block rounded-lg bg-surface px-5 py-5 shadow-[var(--shadow-border)] transition-opacity duration-150 hover:opacity-80"
                >
                  <p className="truncate text-fg">{g.target}</p>
                  <div className="mt-3 flex items-center justify-between gap-3">
                    <p className="font-display text-2xl tabular-nums tracking-tight">
                      {g.latest.score ?? "—"}
                      {g.latest.grade && (
                        <span className="ml-2 text-base text-muted">{g.latest.grade}</span>
                      )}
                    </p>
                    <ScoreSpark values={g.history} />
                  </div>
                  {g.high > 0 && (
                    <p className="mt-2 font-mono text-xs text-high">{g.high} high still open</p>
                  )}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      {rows === null ? (
        <ul className="mt-10 space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <li key={i} className="h-24 animate-pulse rounded-lg bg-surface" />
          ))}
        </ul>
      ) : rows.length === 0 ? (
        <div className="mt-16 max-w-lg">
          <p className="font-display text-2xl tracking-tight">Nothing on the desk yet</p>
          <p className="mt-3 text-muted">
            Send a live site, a GitHub repository, or a short note about the software. The first
            brief is the one you will keep coming back to.
          </p>
        </div>
      ) : (
        <ul className="mt-10 divide-y divide-border">
          {rows.map((row) => (
            <li key={row.id}>
              <Link
                to="/app/scans/$scanId"
                params={{ scanId: row.id }}
                className="flex flex-col gap-3 py-5 transition-opacity duration-150 hover:opacity-80 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <p className="truncate text-fg">{row.target}</p>
                  <p className="mt-1 line-clamp-2 text-sm text-muted">{row.summary || row.status}</p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  {row.grade && <QuietBadge>Grade {row.grade}</QuietBadge>}
                  {typeof row.score === "number" && (
                    <span className="font-mono text-sm tabular-nums text-muted">{row.score}</span>
                  )}
                  {(row.criticalCount > 0 || row.highCount > 0) && (
                    <QuietBadge>
                      {row.criticalCount + row.highCount} high
                    </QuietBadge>
                  )}
                  <QuietBadge>{row.targetType}</QuietBadge>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
