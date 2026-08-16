import { useEffect } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { SiteHeader } from "@/components/site-header";
import { TargetForm } from "@/components/target-form";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const navigate = useNavigate();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const next = (params.get("t") || params.get("target") || "").trim();
    if (!next) return;
    void navigate({ to: "/r", search: { t: next }, replace: true });
  }, [navigate]);

  return (
    <div className="min-h-dvh">
      <SiteHeader />
      <main>
        <section className="mx-auto grid max-w-6xl gap-14 px-5 pb-20 pt-28 sm:px-8 xl:grid-cols-12 xl:gap-10 xl:pt-36">
          <div className="xl:col-span-7">
            <p className="font-mono text-[0.6875rem] uppercase tracking-[0.18em] text-subtle">
              Report · Polish · Fix
            </p>
            <h1 className="mt-5 font-display text-[2.75rem] leading-[1.05] tracking-tight text-fg sm:text-6xl">
              Drop a site or a repo.
              <span className="mt-2 block text-muted">Leave with the brief.</span>
            </h1>
            <p className="mt-6 max-w-xl text-lg text-muted">
              Honed reads what you shipped — headers, cookies, vendors, mail DNS, craft — and
              returns a scored report, a polish plan, and the exact change to make next.
            </p>
            <div className="mt-10">
              <TargetForm />
            </div>
          </div>
          <aside className="xl:col-span-5 xl:pt-16">
            <div className="rounded-xl bg-surface p-6 shadow-[var(--shadow-border)] sm:p-7">
              <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">
                From a finished brief
              </p>
              <p className="mt-4 font-display text-2xl tracking-tight">Northline, grade C</p>
              <p className="mt-3 text-sm leading-relaxed text-muted">
                Three headers missing. Invoice PDF not scoped to the org. Marketing page still has
                no share card. Fix the edge today; schedule the IDOR test before billing ships.
              </p>
              <ul className="mt-6 space-y-3 text-sm">
                <li className="flex justify-between gap-4 border-t border-border pt-3">
                  <span className="text-high">High · IDOR on invoice PDF</span>
                  <span className="text-subtle">low effort</span>
                </li>
                <li className="flex justify-between gap-4 border-t border-border pt-3">
                  <span className="text-high">High · no CSP</span>
                  <span className="text-subtle">medium</span>
                </li>
                <li className="flex justify-between gap-4 border-t border-border pt-3">
                  <span className="text-medium">Polish · blank empty state</span>
                  <span className="text-subtle">low</span>
                </li>
              </ul>
              <Link
                to="/demo"
                className="mt-6 inline-flex h-11 items-center text-sm text-fg underline-offset-4 hover:underline"
              >
                Read the sample brief
              </Link>
            </div>
          </aside>
        </section>

        <section className="border-t border-border">
          <div className="mx-auto grid max-w-6xl gap-10 px-5 py-16 sm:px-8 md:grid-cols-3">
            {[
              {
                k: "01",
                t: "You send the surface",
                d: "A live URL, a GitHub repository, or a few honest paragraphs about the software.",
              },
              {
                k: "02",
                t: "The desk lights up",
                d: "You watch the pass — host, headers, cookies, DNS, vendors, craft — then the brief lands.",
              },
              {
                k: "03",
                t: "You leave with the work",
                d: "A score, a playbook, copy-ready fixes, a shareable brief — then mark them done and rescan to see what actually moved.",
              },
            ].map((s) => (
              <div key={s.k}>
                <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">{s.k}</p>
                <h2 className="mt-3 font-display text-2xl tracking-tight">{s.t}</h2>
                <p className="mt-3 text-sm leading-relaxed text-muted">{s.d}</p>
              </div>
            ))}
          </div>
        </section>
      </main>
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col gap-2 px-5 py-8 text-sm text-subtle sm:flex-row sm:items-center sm:justify-between sm:px-8">
          <p>Honed — a private brief for public surfaces.</p>
          <p>Not a pentest. Not a scanner. The work after both.</p>
        </div>
      </footer>
    </div>
  );
}
