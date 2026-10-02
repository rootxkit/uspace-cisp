"use client";

// The signed-in console's frame: the status strip first, then the
// navigation by role (an item is hidden below its operation's role; the
// page is still reachable by address and shows the API's 403), the
// account menu with sign-out, and the page. A banner under the
// navigation says what the console can and cannot do: it manages
// subscriptions, deliveries, accounts and re-notification, and never
// edits content (hard rule 2).
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@rootxkit/uspace-ui/ui";
import { ConsoleProvider, loginPath, useConsole } from "./context";
import { navFor } from "./roles";
import { StatusStrip } from "./StatusStrip";
import { Loading, ProblemNotice } from "./ui";

function AccountMenu() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { me } = useConsole();
  const { signOut } = useSession();
  const [failed, setFailed] = useState(false);
  if (me === null) return null;
  return (
    <div className="flex items-center gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="outline" size="sm" data-testid="account-menu">
            {me.account.username}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>
            {t("cisp.console.account.role", { role: t(`cisp.console.role.${me.account.role}`) })}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onSelect={() => {
              setFailed(false);
              signOut()
                .then(() => router.replace(loginPath(lang)))
                .catch(() => setFailed(true));
            }}
          >
            {t("cisp.console.account.sign_out")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {failed && (
        <span role="alert" className="text-xs text-[var(--us-danger)]">
          {t("cisp.console.account.sign_out_failed")}
        </span>
      )}
    </div>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const { me, role, meFailure } = useConsole();
  const base = `/${lang}/console`;
  const items = navFor(role);
  return (
    <div className="flex flex-col">
      <StatusStrip />
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--us-border)] px-4 py-2">
        <nav aria-label={t("cisp.console.nav.label")} className="flex flex-wrap gap-3 text-sm">
          {items.map((i) => {
            const href = `${base}${i.path}`;
            const current = i.path === "" ? pathname === base : pathname.startsWith(href);
            return (
              <Link
                key={i.path}
                href={href}
                aria-current={current ? "page" : undefined}
                className={current ? "font-bold underline underline-offset-4" : "underline-offset-4 hover:underline"}
              >
                {t(i.labelKey)}
              </Link>
            );
          })}
        </nav>
        <AccountMenu />
      </div>
      <p className="m-0 border-b border-[var(--us-border)] px-4 py-1 text-xs text-[var(--us-text-muted)]">
        {t("cisp.console.read_only_notice")}
      </p>
      <div className="flex flex-col gap-4 p-4">
        {meFailure !== null && <ProblemNotice failure={meFailure} />}
        {me === null && meFailure === null ? <Loading /> : children}
      </div>
    </div>
  );
}

/** The signed-in console around a page. */
export function ConsoleShell({ children }: { children: ReactNode }) {
  return (
    <ConsoleProvider>
      <SessionFromMe>
        <Frame>{children}</Frame>
      </SessionFromMe>
    </ConsoleProvider>
  );
}

/** The kit's SessionProvider (sign-out through /_bff/logout), fed from /me. */
function SessionFromMe({ children }: { children: ReactNode }) {
  const { me } = useConsole();
  const session = useMemo(
    () =>
      me === null
        ? null
        : {
            sub: me.account.id,
            roles: [me.account.role],
            realm: "console",
            exp: Math.floor(Date.parse(me.session.expires_at) / 1000),
          },
    [me],
  );
  return <SessionProvider session={session}>{children}</SessionProvider>;
}
