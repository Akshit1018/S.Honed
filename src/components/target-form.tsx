import { useState, type FormEvent } from "react";
import { useNavigate } from "@tanstack/react-router";
import { ArrowRight } from "lucide-react";
import { toast } from "sonner";
import type { Report } from "@/lib/report";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const GUEST_KEY = "honed:last-report";
const PENDING_KEY = "honed:pending-target";

export function stashReport(report: Report) {
  try {
    sessionStorage.setItem(GUEST_KEY, JSON.stringify(report));
  } catch {
    /* ignore */
  }
}

export function readStashedReport(): Report | null {
  try {
    const raw = sessionStorage.getItem(GUEST_KEY);
    return raw ? (JSON.parse(raw) as Report) : null;
  } catch {
    return null;
  }
}

export function stashPendingTarget(target: string) {
  try {
    sessionStorage.setItem(PENDING_KEY, target);
  } catch {
    /* ignore */
  }
}

export function readPendingTarget(): string {
  try {
    return sessionStorage.getItem(PENDING_KEY) ?? "";
  } catch {
    return "";
  }
}

export function TargetForm({
  variant = "hero",
  initial = "",
}: {
  variant?: "hero" | "page";
  initial?: string;
}) {
  const navigate = useNavigate();
  const [target, setTarget] = useState(initial);
  const [notesOpen, setNotesOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  function go(value: string) {
    const next = value.trim();
    if (!next) {
      toast("Paste a URL, a GitHub repo, or a few lines about the software.");
      return;
    }
    setBusy(true);
    stashPendingTarget(next);
    void navigate({ to: "/r", search: { t: next } });
  }

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    e.stopPropagation();
    const fromInput = new FormData(e.currentTarget).get("t");
    go(typeof fromInput === "string" && fromInput.trim() ? fromInput : target);
  }

  return (
    <form
      action="/r"
      method="get"
      onSubmit={onSubmit}
      className={cn("w-full", variant === "hero" && "max-w-xl")}
    >
      <div className="rounded-xl bg-surface p-2 shadow-[var(--shadow-border)]">
        {notesOpen ? (
          <Textarea
            name="t"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Describe the software: what it does, who uses it, auth, payments, uploads, anything that worries you."
            aria-label="Software brief"
            disabled={busy}
          />
        ) : (
          <Input
            name="t"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://your-site.com  or  github.com/org/repo"
            aria-label="Site or repository"
            autoComplete="url"
            inputMode="url"
            disabled={busy}
          />
        )}
        <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            className="h-11 px-3 text-left text-sm text-muted transition-colors duration-150 hover:text-fg"
            onClick={() => setNotesOpen((v) => !v)}
          >
            {notesOpen ? "Use a URL instead" : "Or describe the software"}
          </button>
          <Button type="submit" size="lg" disabled={busy} className="w-full sm:w-auto">
            {busy ? (
              "Opening desk"
            ) : (
              <>
                Inspect
                <ArrowRight className="size-4" />
              </>
            )}
          </Button>
        </div>
      </div>
      <p className="mt-3 px-1 text-sm text-subtle">
        Passive only — we fetch the public page or repo. No exploits, no logins, no writes.
      </p>
    </form>
  );
}
