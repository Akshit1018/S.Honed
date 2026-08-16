import { useEffect, useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { SiteHeader } from "@/components/site-header";
import { ReportView } from "@/components/report-view";
import { getShare } from "@/lib/share";
import type { Report } from "@/lib/report";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/s/$token")({
  component: SharedBrief,
});

function SharedBrief() {
  const { token } = Route.useParams();
  const [state, setState] = useState<
    | { status: "loading" }
    | { status: "missing"; message: string }
    | { status: "ready"; report: Report }
  >({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    void getShare({ data: { token } })
      .then((row) => {
        if (cancelled) return;
        setState({ status: "ready", report: row.report });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setState({
          status: "missing",
          message: err instanceof Error ? err.message : "Brief not found.",
        });
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="min-h-dvh">
      <SiteHeader solid />
      {state.status === "loading" ? (
        <section className="mx-auto max-w-xl px-5 py-24 text-center">
          <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">
            Shared brief
          </p>
          <p className="mt-4 text-muted">Opening the desk…</p>
        </section>
      ) : state.status === "missing" ? (
        <section className="mx-auto max-w-xl px-5 py-24 text-center">
          <h1 className="font-display text-4xl tracking-tight">Link is dead</h1>
          <p className="mt-4 text-muted">{state.message}</p>
          <Button asChild className="mt-8">
            <Link to="/">Inspect something else</Link>
          </Button>
        </section>
      ) : (
        <ReportView
          report={state.report}
          footer={
            <div className="rounded-xl bg-surface p-6 shadow-[var(--shadow-border)] sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="font-display text-2xl tracking-tight">Run this again</p>
                <p className="mt-2 max-w-md text-sm text-muted">
                  This is a snapshot. Inspect the live origin to see what changed.
                </p>
              </div>
              <Button asChild className="mt-4 sm:mt-0">
                <Link to="/r" search={{ t: state.report.finalUrl || state.report.target }}>
                  Inspect live
                </Link>
              </Button>
            </div>
          }
        />
      )}
    </div>
  );
}
