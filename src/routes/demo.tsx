import { createFileRoute } from "@tanstack/react-router";
import { SiteHeader } from "@/components/site-header";
import { ReportView } from "@/components/report-view";
import { SAMPLE_REPORT } from "@/lib/sample-report";

export const Route = createFileRoute("/demo")({ component: Demo });

function Demo() {
  return (
    <div className="min-h-dvh">
      <SiteHeader solid />
      <ReportView report={SAMPLE_REPORT} sample />
    </div>
  );
}
