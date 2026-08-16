import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { RedirectToSignIn } from "@/lib/auth/gates";
import { useCurrentUserState } from "@/lib/auth/use-current-user";
import { signOut } from "@/lib/auth/client";
import { Mark } from "@/components/mark";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/app")({ component: AppLayout });

function AppLayout() {
  const { user, isPending } = useCurrentUserState();

  if (isPending) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <div className="h-8 w-32 animate-pulse rounded-sm bg-elevated" />
      </div>
    );
  }
  if (!user) return <RedirectToSignIn />;

  return (
    <div className="min-h-dvh">
      <header className="sticky top-0 z-30 border-b border-border/80 bg-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 sm:px-8">
          <Link to="/" className="rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50">
            <Mark />
          </Link>
          <div className="flex items-center gap-1">
            <Button asChild variant="ghost" size="sm">
              <Link to="/app">Work</Link>
            </Button>
            <Button asChild size="sm">
              <Link to="/app/new">New brief</Link>
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={() => void signOut()}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <Outlet />
    </div>
  );
}
