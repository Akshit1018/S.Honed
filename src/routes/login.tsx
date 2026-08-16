import { createFileRoute, Link } from "@tanstack/react-router";
import { GROK_PROVIDERS, authEnabled, signIn } from "@/lib/auth/client";
import { Mark } from "@/components/mark";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/login")({ component: Login });

function Login() {
  return (
    <main className="grid min-h-dvh place-items-center px-5 py-16">
      <div className="w-full max-w-sm">
        <Link to="/" className="inline-flex">
          <Mark />
        </Link>
        <h1 className="mt-10 font-display text-4xl tracking-tight">Sign in to keep the work</h1>
        <p className="mt-3 text-sm text-muted">
          Guest inspections are ephemeral. An account saves briefs and deepens the polish plan.
        </p>
        <div className="mt-8 space-y-2">
          {authEnabled ? (
            GROK_PROVIDERS.map((p) => (
              <Button
                key={p.providerId}
                type="button"
                variant="outline"
                className="w-full"
                onClick={() => signIn(p.providerId, { callbackURL: "/app" })}
              >
                Continue with {p.label}
              </Button>
            ))
          ) : (
            <p className="text-sm text-muted">Sign-in is disabled in this environment.</p>
          )}
        </div>
        <p className="mt-8 text-sm text-subtle">
          <Link to="/" className="underline-offset-4 hover:text-fg hover:underline">
            Back to Honed
          </Link>
        </p>
      </div>
    </main>
  );
}
