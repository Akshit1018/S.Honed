import { cn } from "@/lib/utils";

export function Mark({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-2 text-fg", className)}>
      <svg viewBox="0 0 24 24" className="size-5 shrink-0" aria-hidden="true">
        <rect width="24" height="24" rx="5" className="fill-accent" />
        <path
          d="M6.4 17V7h2.35c2.15 0 3.45 1.12 3.45 2.95 0 1.12-.52 2-1.5 2.48L13.8 17h-2.5l-2.6-3.75H8.85V17H6.4zm2.2-5.5h.15c1 0 1.55-.5 1.55-1.38S9.75 8.75 8.75 8.75H8.6V11.5z"
          className="fill-accent-fg"
        />
        <rect x="16.2" y="7" width="1.25" height="10" rx="0.4" className="fill-accent-fg" />
      </svg>
      <span className="font-display text-lg tracking-tight">Honed</span>
    </span>
  );
}
