import { createFileRoute } from "@tanstack/react-router";
import { TargetForm } from "@/components/target-form";

export const Route = createFileRoute("/app/new")({ component: NewBrief });

function NewBrief() {
  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-16 sm:px-8">
      <p className="font-mono text-[0.6875rem] uppercase tracking-[0.16em] text-subtle">New brief</p>
      <h1 className="mt-3 font-display text-4xl tracking-tight sm:text-5xl">What should we read?</h1>
      <p className="mt-4 max-w-lg text-muted">
        A public URL, a GitHub repository, or a plain-language note about the software. Signed-in
        briefs are saved and get a written polish pass.
      </p>
      <div className="mt-10">
        <TargetForm variant="page" />
      </div>
    </main>
  );
}
