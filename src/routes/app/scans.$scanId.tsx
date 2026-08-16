import { useEffect, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { getScan, rescanScan } from "@/lib/scans";
import type { Report } from "@/lib/report";
import { ReportView } from "@/components/report-view";
import { ScanTheater } from "@/components/scan-theater";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/app/scans/$scanId")({ component: SavedBrief });

function SavedBrief() {
  const { scanId } = Route.useParams();
  const navigate = useNavigate();
  const [rescanning, setRescanning] = useState(false);
  const [state, setState] = useState<
    | { status: "loading" }
    | { status: "missing"; message: string }
    | { status: "ready"; target: string; report: Report | null; error: string | null }
  >({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    void getScan({ data: { id: scanId } })
      .then((row) => {
        if (cancelled) return;
        setState({
          status: "ready",
          target: row.target,
          report: row.report,
          error: row.error,
        });
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
  }, [scanId]);

  async function rescan() {
    setRescanning(true);
    try {
      const { id } = await rescanScan({ data: { id: scanId } });
      await navigate({ to: "/app/scans/$scanId", params: { scanId: id } });
    } catch (err) {
      toast(err instanceof Error ? err.message : "Rescan failed.");
    } finally {
      setRescanning(false);
    }
  }

  if (state.status === "loading") {
    return <ScanTheater target="Opening the brief" />;
  }
  if (state.status === "missing") {
    return (
      <section className="mx-auto max-w-xl px-5 py-24 text-center">
        <h1 className="font-display text-4xl tracking-tight">No brief here</h1>
        <p className="mt-4 text-muted">{state.message}</p>
        <Button asChild className="mt-8">
          <Link to="/app">Back to work</Link>
        </Button>
      </section>
    );
  }
  if (state.error || !state.report) {
    return (
      <section className="mx-auto max-w-xl px-5 py-24 text-center">
        <h1 className="font-display text-4xl tracking-tight">This one failed</h1>
        <p className="mt-4 text-muted">{state.error || "The inspection did not finish."}</p>
        <Button asChild className="mt-8">
          <Link to="/app/new">Try again</Link>
        </Button>
      </section>
    );
  }
  return (
    <ReportView
      report={state.report}
      scanId={scanId}
      canAsk
      onRescan={() => void rescan()}
      rescanning={rescanning}
    />
  );
}
