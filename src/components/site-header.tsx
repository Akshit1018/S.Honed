import { Link } from "@tanstack/react-router";
import { useCurrentUserState } from "@/lib/auth/use-current-user";
import { signOut } from "@/lib/auth/client";
import { Mark } from "@/components/mark";
import { Button } from "@/components/ui/button";

export function SiteHeader({ solid = false }: { solid?: boolean }) {
  const { user, isPending } = useCurrentUserState();

  return (
    <header
      className={
        solid
          ? "sticky top-0 z-30 border-b border-border/80 bg-bg/90 backdrop-blur-sm"
          : "absolute inset-x-0 top-0 z-30"
      }
    >
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5 sm:px-8">
        <Link to="/" className="rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50">
          <Mark />
        </Link>
        <nav className="flex items-center gap-1 sm:gap-2">
          <Link
            to="/demo"
            className="hidden h-11 items-center px-3 text-sm text-muted transition-colors duration-150 hover:text-fg sm:inline-flex"
          >
            Sample brief
          </Link>
          {isPending ? (
            <div className="h-8 w-24 animate-pulse rounded-sm bg-elevated" />
          ) : user ? (
            <>
              <Button asChild variant="ghost" size="sm">
                <Link to="/app">Work</Link>
              </Button>
              <Button type="button" variant="ghost" size="sm" onClick={() => void signOut()}>
                Sign out
              </Button>
            </>
          ) : (
            <Button asChild variant="outline" size="sm">
              <Link to="/login">Sign in</Link>
            </Button>
          )}
        </nav>
      </div>
    </header>
  );
}
