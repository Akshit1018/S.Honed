import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Check, Copy, Download, Printer, RefreshCw, Share2 } from "lucide-react";
import { toast } from "sonner";
import type { Finding, FindingKind, Report, Severity, WorkStatus } from "@/lib/report";
import { countBySeverity } from "@/lib/report";
import {
  cookiePackText,
  findingToGithubIssue,
  headerPackText,
  reportToJson,
  reportToMarkdown,
} from "@/lib/report-extra";
import { askFinding, listFindingStatuses, setFindingStatus } from "@/lib/work";
import { createShare } from "@/lib/share";
import { SeverityBadge, QuietBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const TABS: { id: "overview" | "playbook" | "surface" | "vendors" | FindingKind; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "security", label: "Security" },
  { id: "polish", label: "Polish" },
  { id: "playbook", label: "Playbook" },
  { id: "solution", label: "Fixes" },
  { id: "vendors", label: "Vendors" },
  { id: "surface", label: "Surface" },
];

const SEV_CHIPS: { id: Severity | "all"; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" },
];

function slug(report: Report) {
  return (report.pageTitle || report.target)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);
}

function guestKey(target: string) {
  return `honed:work:${target}`;
}

function readGuestWork(target: string): Record<string, WorkStatus> {
  try {
    const raw = sessionStorage.getItem(guestKey(target));
    return raw ? (JSON.parse(raw) as Record<string, WorkStatus>) : {};
  } catch {
    return {};
  }
}

function downloadText(name: string, text: string, type: string) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function ReportView({
  report,
  sample = false,
  footer,
  scanId,
  canAsk = false,
  onRescan,
  rescanning = false,
}: {
  report: Report;
  sample?: boolean;
  footer?: ReactNode;
  scanId?: string;
  canAsk?: boolean;
  onRescan?: () => void;
  rescanning?: boolean;
}) {
  const [tab, setTab] = useState<(typeof TABS)[number]["id"]>("overview");
  const [query, setQuery] = useState("");
  const [hideDone, setHideDone] = useState(false);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [work, setWork] = useState<Record<string, WorkStatus>>({});
  const [sharing, setSharing] = useState(false);

  useEffect(() => {
    if (!scanId) {
      setWork(readGuestWork(report.target));
      return;
    }
    void listFindingStatuses({ data: { scanId } })
      .then((rows) => {
        const next: Record<string, WorkStatus> = {};
        for (const r of rows) next[r.findingId] = r.status;
        setWork(next);
      })
      .catch(() => setWork({}));
  }, [scanId, report.target]);

  async function updateWork(findingId: string, status: WorkStatus) {
    setWork((prev) => {
      const next = { ...prev, [findingId]: status };
      if (!scanId) sessionStorage.setItem(guestKey(report.target), JSON.stringify(next));
      return next;
    });
    if (scanId) {
      try {
        await setFindingStatus({ data: { scanId, findingId, status } });
      } catch (err) {
        toast(err instanceof Error ? err.message : "Could not save status.");
      }
    }
  }

  const counts = useMemo(() => countBySeverity(report.findings), [report.findings]);
  const byId = useMemo(() => new Map(report.findings.map((f) => [f.id, f])), [report.findings]);

  const list = useMemo(() => {
    let items: Finding[] = [];
    if (tab === "overview") items = report.findings.filter((f) => f.kind !== "solution").slice(0, 6);
    else if (tab === "playbook") {
      items = (report.playbook ?? []).map((id) => byId.get(id)).filter(Boolean) as Finding[];
    } else if (tab === "solution") {
      items = report.findings.filter((f) => f.kind === "solution" || Boolean(f.fix));
    } else if (tab === "surface" || tab === "vendors") items = [];
    else items = report.findings.filter((f) => f.kind === tab);

    const q = query.trim().toLowerCase();
    if (q) {
      items = items.filter((f) =>
        `${f.title} ${f.summary} ${f.cwe ?? ""} ${f.owasp ?? ""}`.toLowerCase().includes(q),
      );
    }
    if (sev !== "all") {
      items = items.filter((f) => (sev === "low" ? f.severity === "low" || f.severity === "info" : f.severity === sev));
    }
    if (hideDone) items = items.filter((f) => work[f.id] !== "done");
    return items;
  }, [tab, report, byId, query, hideDone, work, sev]);

  function exportMarkdown() {
    downloadText(`${slug(report) || "brief"}.md`, reportToMarkdown(report), "text/markdown;charset=utf-8");
  }

  function exportJson() {
    downloadText(`${slug(report) || "brief"}.json`, reportToJson(report), "application/json;charset=utf-8");
  }

  async function copyHeaders() {
    try {
      await navigator.clipboard.writeText(headerPackText());
      toast("Header pack copied.");
    } catch {
      toast("Could not copy.");
    }
  }

  async function copyCookies() {
    try {
      await navigator.clipboard.writeText(cookiePackText());
      toast("Cookie pack copied.");
    } catch {
      toast("Could not copy.");
    }
  }

  async function shareBrief() {
    setSharing(true);
    try {
      const { token } = await createShare({ data: { report } });
      const url = `${window.location.origin}/s/${token}`;
      await navigator.clipboard.writeText(url);
      toast("Share link copied.");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not share.");
    } finally {
      setSharing(false);
    }
  }

  const doneCount = report.findings.filter((f) => work[f.id] === "done").length;
  const cookieIssues = (report.cookies ?? []).filter((c) => c.issues.length > 0).length;

  return (
    <article className="mx-auto w-full max-w-5xl px-5 pb-24 pt-10 sm:px-8">
      <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">
        {sample ? "Sample brief" : report.targetType === "notes" ? "Software brief" : "Inspection"}
        {report.enriched ? " · deepened" : ""}
        {doneCount > 0 ? ` · ${doneCount} marked done` : ""}
      </p>
      <div className="mt-3 flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <h1 className="font-display text-4xl tracking-tight text-fg sm:text-5xl">
            {report.pageTitle || report.target}
          </h1>
          <p className="mt-3 max-w-2xl text-muted break-all">{report.finalUrl || report.target}</p>
        </div>
        <ScoreMark score={report.score} grade={report.grade} compare={report.compare} />
      </div>

      {report.compare && (
        <div className="mt-6 rounded-lg bg-surface px-5 py-4 shadow-[var(--shadow-border)]">
          <p className="text-sm text-muted">
            Last brief was {report.compare.previousScore}
            {report.compare.previousGrade ? ` (${report.compare.previousGrade})` : ""}. This pass is{" "}
            <span className="text-fg tabular-nums">
              {report.compare.delta > 0 ? "+" : ""}
              {report.compare.delta}
            </span>
            .
          </p>
          {(report.compare.resolved?.length || report.compare.added?.length) && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {!!report.compare.resolved?.length && (
                <div>
                  <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-low">Resolved</p>
                  <ul className="mt-2 space-y-1 text-sm text-muted">
                    {report.compare.resolved.map((t) => (
                      <li key={t}>{t}</li>
                    ))}
                  </ul>
                </div>
              )}
              {!!report.compare.added?.length && (
                <div>
                  <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-high">New</p>
                  <ul className="mt-2 space-y-1 text-sm text-muted">
                    {report.compare.added.map((t) => (
                      <li key={t}>{t}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="mt-8 flex flex-wrap gap-2 no-print">
        <Button type="button" variant="outline" size="sm" onClick={() => window.print()}>
          <Printer className="size-4" />
          Print
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={exportMarkdown}>
          <Download className="size-4" />
          Markdown
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={exportJson}>
          <Download className="size-4" />
          JSON
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => void copyHeaders()}>
          <Copy className="size-4" />
          Header pack
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => void copyCookies()}>
          <Copy className="size-4" />
          Cookie pack
        </Button>
        {!sample && (
          <Button type="button" variant="outline" size="sm" disabled={sharing} onClick={() => void shareBrief()}>
            <Share2 className="size-4" />
            {sharing ? "Sharing" : "Share"}
          </Button>
        )}
        {onRescan && (
          <Button type="button" variant="outline" size="sm" disabled={rescanning} onClick={onRescan}>
            <RefreshCw className={cn("size-4", rescanning && "animate-spin")} />
            {rescanning ? "Reading" : "Rescan"}
          </Button>
        )}
      </div>

      <dl className="mt-10 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {(
          [
            ["critical", counts.critical],
            ["high", counts.high],
            ["medium", counts.medium],
            ["low", counts.low + counts.info],
          ] as const
        ).map(([k, v]) => (
          <div key={k} className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
            <dt className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">{k}</dt>
            <dd className="mt-2 font-display text-3xl tabular-nums tracking-tight">{v}</dd>
          </div>
        ))}
      </dl>

      <p className="mt-10 max-w-3xl text-lg leading-relaxed text-fg">{report.summary}</p>

      {report.tech.length > 0 && (
        <div className="mt-6 flex flex-wrap gap-2">
          {report.tech.map((t) => (
            <QuietBadge key={t}>{t}</QuietBadge>
          ))}
        </div>
      )}

      {report.headers && report.headers.length > 0 && (
        <ul className="mt-10 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {report.headers.map((h) => (
            <li key={h.name} className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
              <p className="flex items-center justify-between gap-2">
                <span className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
                  {h.name}
                </span>
                <span className={h.present ? "text-low" : "text-high"}>{h.present ? "on" : "off"}</span>
              </p>
              <p className="mt-2 text-sm text-muted">{h.note}</p>
            </li>
          ))}
        </ul>
      )}

      {report.cookies && report.cookies.length > 0 && (
        <div className="mt-8">
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
            Cookies{cookieIssues > 0 ? ` · ${cookieIssues} weak` : ""}
          </p>
          <ul className="mt-3 grid gap-2 sm:grid-cols-2">
            {report.cookies.map((c) => (
              <li key={c.name} className="rounded-lg bg-surface px-4 py-4 shadow-[var(--shadow-border)]">
                <p className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-sm text-fg">{c.name}</span>
                  <span className={c.issues.length ? "text-high" : "text-low"}>
                    {c.issues.length ? "weak" : "locked"}
                  </span>
                </p>
                <p className="mt-2 font-mono text-xs text-muted">
                  {c.secure ? "Secure" : "no-Secure"} · {c.httpOnly ? "HttpOnly" : "no-HttpOnly"} ·{" "}
                  {c.sameSite ? `SameSite=${c.sameSite}` : "no-SameSite"}
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-12 flex flex-wrap gap-1 border-b border-border no-print">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={cn(
              "h-11 px-4 text-sm transition-colors duration-150",
              tab === t.id ? "text-fg" : "text-muted hover:text-fg",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab !== "surface" && tab !== "vendors" && (
        <div className="mt-6 flex flex-col gap-3 no-print">
          <div className="flex flex-wrap gap-1">
            {SEV_CHIPS.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setSev(c.id)}
                className={cn(
                  "h-10 px-3 text-sm transition-colors duration-150",
                  sev === c.id ? "text-fg" : "text-muted hover:text-fg",
                )}
              >
                {c.label}
              </button>
            ))}
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter findings"
              aria-label="Filter findings"
              className="h-11 w-full rounded-md bg-elevated px-4 text-sm text-fg shadow-[var(--shadow-border)] outline-none placeholder:text-subtle sm:max-w-xs"
            />
            <label className="inline-flex h-11 items-center gap-2 text-sm text-muted">
              <input
                type="checkbox"
                checked={hideDone}
                onChange={(e) => setHideDone(e.target.checked)}
                className="size-4 accent-accent"
              />
              Hide done
            </label>
          </div>
        </div>
      )}

      {tab === "overview" && (
        <ul className="mt-8 grid gap-3 sm:grid-cols-2">
          {report.agents.map((a) => (
            <li key={a.name} className="rounded-lg bg-surface px-5 py-5 shadow-[var(--shadow-border)]">
              <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
                {a.name} · {a.role}
              </p>
              <p className="mt-2 text-sm text-fg">{a.note}</p>
            </li>
          ))}
        </ul>
      )}

      {tab === "surface" ? (
        <ul className="mt-8 space-y-3">
          {(report.surface ?? []).length === 0 && !(report.dns ?? []).length ? (
            <li className="text-sm text-muted">No well-known files were probed on this brief.</li>
          ) : (
            <>
              {(report.surface ?? []).map((s) => (
                <li key={s.id} className="rounded-lg bg-surface px-5 py-5 shadow-[var(--shadow-border)]">
                  <p className="flex items-center justify-between gap-3">
                    <span className="font-mono text-sm text-fg">{s.label}</span>
                    <QuietBadge>{s.status}</QuietBadge>
                  </p>
                  <p className="mt-2 text-sm text-muted">{s.detail}</p>
                </li>
              ))}
              {(report.dns ?? []).map((s) => (
                <li key={s.id} className="rounded-lg bg-surface px-5 py-5 shadow-[var(--shadow-border)]">
                  <p className="flex items-center justify-between gap-3">
                    <span className="font-mono text-sm text-fg">{s.label}</span>
                    <QuietBadge>{s.status}</QuietBadge>
                  </p>
                  <p className="mt-2 text-sm text-muted">{s.detail}</p>
                </li>
              ))}
            </>
          )}
        </ul>
      ) : tab === "vendors" ? (
        <ul className="mt-8 space-y-3">
          {(report.vendors ?? []).length === 0 ? (
            <li className="text-sm text-muted">No third-party hosts on the first document.</li>
          ) : (
            report.vendors!.map((v) => (
              <li key={`${v.host}-${v.kind}`} className="rounded-lg bg-surface px-5 py-5 shadow-[var(--shadow-border)]">
                <p className="flex flex-wrap items-center justify-between gap-3">
                  <span className="font-mono text-sm text-fg">{v.host}</span>
                  <span className="flex gap-2">
                    <QuietBadge>{v.kind}</QuietBadge>
                    <QuietBadge>{v.category}</QuietBadge>
                    {v.sri && <QuietBadge>SRI</QuietBadge>}
                  </span>
                </p>
                <p className="mt-2 break-all font-mono text-xs text-subtle">{v.sample}</p>
              </li>
            ))
          )}
        </ul>
      ) : (
        <ul className="mt-8 space-y-4">
          {list.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              emphasizeFix={tab === "solution" || tab === "playbook"}
              status={work[f.id] ?? "open"}
              onStatus={(s) => void updateWork(f.id, s)}
              canAsk={canAsk}
              target={report.target}
            />
          ))}
          {list.length === 0 && tab !== "overview" && (
            <li className="text-sm text-muted">Nothing in this view.</li>
          )}
        </ul>
      )}

      {footer && <div className="mt-12 no-print">{footer}</div>}

      {sample && (
        <p className="mt-10 text-sm text-subtle no-print">
          This is a finished sample.{" "}
          <Link to="/" className="text-fg underline-offset-4 hover:underline">
            Inspect a real site
          </Link>{" "}
          to generate your own.
        </p>
      )}
    </article>
  );
}

function ScoreMark({
  score,
  grade,
  compare,
}: {
  score: number;
  grade: string;
  compare?: Report["compare"];
}) {
  return (
    <div className="text-right">
      <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">Score</p>
      <p className="font-display text-5xl tabular-nums tracking-tight">
        {score}
        <span className="ml-2 text-2xl text-muted">{grade}</span>
      </p>
      {compare && (
        <p className="mt-1 font-mono text-xs tabular-nums text-subtle">
          {compare.delta > 0 ? "+" : ""}
          {compare.delta} vs last
        </p>
      )}
    </div>
  );
}

function FindingCard({
  finding,
  emphasizeFix,
  status,
  onStatus,
  canAsk,
  target,
}: {
  finding: Finding;
  emphasizeFix: boolean;
  status: WorkStatus;
  onStatus: (s: WorkStatus) => void;
  canAsk: boolean;
  target: string;
}) {
  const [ask, setAsk] = useState("");
  const [answer, setAnswer] = useState<string | null>(null);
  const [asking, setAsking] = useState(false);

  async function copyFix() {
    try {
      await navigator.clipboard.writeText(finding.fix);
      toast("Fix copied.");
    } catch {
      toast("Could not copy.");
    }
  }

  async function copyIssue() {
    try {
      await navigator.clipboard.writeText(findingToGithubIssue(finding, target));
      toast("GitHub issue copied.");
    } catch {
      toast("Could not copy.");
    }
  }

  async function submitAsk() {
    const q = ask.trim();
    if (!q) return;
    setAsking(true);
    try {
      const res = await askFinding({
        data: {
          question: q,
          title: finding.title,
          summary: finding.summary,
          detail: finding.detail,
          fix: finding.fix,
          target,
        },
      });
      if (res.ok) setAnswer(res.text);
      else toast(res.error);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not ask.");
    } finally {
      setAsking(false);
    }
  }

  return (
    <li className="rounded-xl bg-surface p-5 shadow-[var(--shadow-border)] sm:p-6">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <QuietBadge>{finding.kind}</QuietBadge>
        {finding.cwe && <QuietBadge>{finding.cwe}</QuietBadge>}
        {finding.owasp && <QuietBadge>{finding.owasp}</QuietBadge>}
        {typeof finding.cvss === "number" && <QuietBadge>CVSS {finding.cvss}</QuietBadge>}
        <QuietBadge>{finding.effort} effort</QuietBadge>
      </div>
      <h2 className="mt-4 font-display text-2xl tracking-tight text-fg">{finding.title}</h2>
      <p className="mt-2 text-muted">{finding.summary}</p>
      <p className="mt-3 text-sm leading-relaxed text-fg">{finding.detail}</p>
      {finding.location && <p className="mt-3 font-mono text-xs text-subtle">{finding.location}</p>}
      {finding.evidence && (
        <pre className="mt-3 overflow-x-auto rounded-md bg-elevated p-3 font-mono text-xs text-muted">
          {finding.evidence}
        </pre>
      )}

      {(emphasizeFix || finding.kind === "solution") && (
        <div className="mt-5 rounded-md bg-elevated p-4">
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
            {finding.fixTitle}
          </p>
          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-sm text-fg">
            {finding.fix}
          </pre>
        </div>
      )}
      {!emphasizeFix && finding.kind !== "solution" && (
        <details className="mt-4">
          <summary className="cursor-pointer text-sm text-muted hover:text-fg">Show the fix</summary>
          <div className="mt-3 rounded-md bg-elevated p-4">
            <p className="font-mono text-[0.6875rem] uppercase tracking-[0.14em] text-subtle">
              {finding.fixTitle}
            </p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-sm text-fg">
              {finding.fix}
            </pre>
          </div>
        </details>
      )}

      <div className="mt-5 flex flex-wrap gap-2 no-print">
        {(["open", "doing", "done"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onStatus(s)}
            className={cn(
              "inline-flex h-10 items-center gap-1 rounded-sm px-3 text-sm transition-colors duration-150",
              status === s ? "bg-elevated text-fg" : "text-muted hover:text-fg",
            )}
          >
            {s === "done" && <Check className="size-3.5" />}
            {s}
          </button>
        ))}
        <button
          type="button"
          onClick={() => void copyFix()}
          className="inline-flex h-10 items-center gap-1 px-3 text-sm text-muted hover:text-fg"
        >
          <Copy className="size-3.5" />
          Copy fix
        </button>
        <button
          type="button"
          onClick={() => void copyIssue()}
          className="inline-flex h-10 items-center gap-1 px-3 text-sm text-muted hover:text-fg"
        >
          <Copy className="size-3.5" />
          GitHub issue
        </button>
      </div>

      {canAsk && (
        <form
          className="mt-4 no-print"
          onSubmit={(e) => {
            e.preventDefault();
            void submitAsk();
          }}
        >
          <label className="sr-only" htmlFor={`ask-${finding.id}`}>
            Ask about this finding
          </label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              id={`ask-${finding.id}`}
              value={ask}
              onChange={(e) => setAsk(e.target.value)}
              placeholder="Ask how to ship this fix"
              className="h-11 flex-1 rounded-md bg-elevated px-4 text-sm text-fg shadow-[var(--shadow-border)] outline-none placeholder:text-subtle"
            />
            <Button type="submit" variant="outline" size="sm" disabled={asking}>
              {asking ? "Thinking" : "Ask"}
            </Button>
          </div>
          {answer && <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed text-muted">{answer}</p>}
        </form>
      )}
    </li>
  );
}
