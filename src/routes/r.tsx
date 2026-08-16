import { useEffect, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { SiteHeader } from "@/components/site-header";
import { ReportView } from "@/components/report-view";
import { ScanTheater } from "@/components/scan-theater";
import { readPendingTarget, stashReport } from "@/components/target-form";
import { Button } from "@/components/ui/button";
import { inspectTarget, saveGuestReport } from "@/lib/scans";
import type { Report } from "@/lib/report";
import { compareReports } from "@/lib/report-extra";
import { useCurrentUser } from "@/lib/auth/use-current-user";
import { toast } from "sonner";

type Search = { t: string };

export const Route = createFileRoute("/r")({
  validateSearch: (raw: Record<string, unknown>): Search => ({
    t: typeof raw.t === "string" ? raw.t : typeof raw.target === "string" ? String(raw.target) : "",
  }),
  component: GuestBrief,
});

function GuestBrief() {
  const search = Route.useSearch();
  const user = useCurrentUser();
  const navigate = useNavigate();
  const [target, setTarget] = useState(search.t);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    const next = search.t.trim() || readPendingTarget().trim();
    setTarget(next);
    if (!next) {
      setError("Nothing to inspect.");
      setReport(null);
      return;
    }

    let cancelled = false;
    const started = Date.now();
    setReport(null);
    setError(null);

    void inspectTarget({ data: { target: next } })
      .then(async (r) => {
        const wait = Math.max(0, 1800 - (Date.now() - started));
        if (wait) await new Promise((res) => setTimeout(res, wait));
        if (cancelled) return;
        stashReport(r);
        setReport(r);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Inspection failed.");
      });

    return () => {
      cancelled = true;
    };
  }, [search.t]);

  async function save() {
    if (!report) return;
    setSaving(true);
    try {
      const { id } = await saveGuestReport({ data: { report } });
      await navigate({ to: "/app/scans/$scanId", params: { scanId: id } });
    } catch (err) {
      toast(err instanceof Error ? err.message : "Could not save.");
    } finally {
      setSaving(false);
    }
  }

  async function rescan() {
    const next = target || report?.target;
    if (!next) return;
    setRescanning(true);
    setError(null);
    const previous = report;
    setReport(null);
    try {
      const r = await inspectTarget({ data: { target: next } });
      const nextReport = previous ? { ...r, compare: compareReports(previous, r) } : r;
      stashReport(nextReport);
      setReport(nextReport);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Inspection failed.");
    } finally {
      setRescanning(false);
    }
  }

  return (
    <div className="min-h-dvh">
      <SiteHeader solid />
      {error ? (
        <section className="mx-auto max-w-xl px-5 py-24 text-center">
          <h1 className="font-display text-4xl tracking-tight">Could not read that</h1>
          <p className="mt-4 text-muted">{error}</p>
          <Button asChild className="mt-8">
            <Link to="/">Try another</Link>
          </Button>
        </section>
      ) : !report ? (
        <ScanTheater target={target || "your target"} />
      ) : (
        <ReportView
          report={report}
          onRescan={() => void rescan()}
          rescanning={rescanning}
          footer={
            <div className="rounded-xl bg-surface p-6 shadow-[var(--shadow-border)] sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="font-display text-2xl tracking-tight">Keep this brief</p>
                <p className="mt-2 max-w-md text-sm text-muted">
                  Sign in to save it, track fixes, and deepen the polish plan with a written pass.
                </p>
              </div>
              {user ? (
                <Button className="mt-4 sm:mt-0" disabled={saving} onClick={() => void save()}>
                  {saving ? "Saving" : "Save to my work"}
                </Button>
              ) : (
                <Button asChild className="mt-4 sm:mt-0">
                  <Link to="/login">Sign in to save</Link>
                </Button>
              )}
            </div>
          }
        />
      )}
    </div>
  );
}
