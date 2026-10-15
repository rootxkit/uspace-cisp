"use client";

// The signed-in console's frame: the kit's AppShell. The sidebar holds
// the navigation by role in its groups (an item is hidden below its
// operation's role; the page is still reachable by address and shows the
// API's 403); the top bar the system name, the stream's live/stale pill,
// the scheme toggle, the language switch and the account menu with
// sign-out. Above every page, the status strip, where the operator looks
// first; below every page, a note of what the console can and cannot do: it manages
// subscriptions, deliveries, accounts and re-notification, and never
// edits content (hard rule 2).
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import { SessionProvider, useSession } from "@rootxkit/uspace-ui/auth/client";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useFeed, useNowMs, type LiveFeed } from "@rootxkit/uspace-ui/live";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { AppShell, DropdownMenuItem, StatusPill, UserMenu, type FeedPillState, type NavGroup } from "@rootxkit/uspace-ui/ui";
import { BrandMark, renderLink, SchemeToggle } from "../components/frame";
import {
  AccountsIcon,
  AuditIcon,
  ExternalIcon,
  OverviewIcon,
  PublicationsIcon,
  RestrictionsIcon,
  SignOutIcon,
  SubscriptionsIcon,
} from "../components/icons";
import { useRuntimeConfig } from "../components/Providers";
import { ConsoleProvider, loginPath, useConsole } from "./context";
import { navFor } from "./roles";
import { StatusStrip } from "./StatusStrip";
import { Loading, ProblemNotice } from "./ui";

/** How often the ages on the frame are redrawn. Display-only. */
const TICK_MS = 1000;

/** The sidebar's groups, in order, and the group and icon of each console page. */
const GROUPS = ["monitor", "data", "distribution", "admin"] as const;
type Group = (typeof GROUPS)[number];
const PLACE: Record<string, { group: Group; icon: ReactNode }> = {
  "": { group: "monitor", icon: <OverviewIcon /> },
  "/publications": { group: "data", icon: <PublicationsIcon /> },
  "/restrictions": { group: "data", icon: <RestrictionsIcon /> },
  "/subscriptions": { group: "distribution", icon: <SubscriptionsIcon /> },
  "/accounts": { group: "admin", icon: <AccountsIcon /> },
  "/audit": { group: "admin", icon: <AuditIcon /> },
};

/**
 * The pill's state from the stream: connecting and down as the kit's feed
 * says; live is stale once the last frame is older than the stale_after_s
 * the server's status frame sent (the server's bound, never one of ours).
 */
export function pillState(feed: Pick<LiveFeed, "connection" | "staleAfterS">, ageS: number | null): FeedPillState {
  if (feed.connection !== "live") return feed.connection;
  return feed.staleAfterS !== null && ageS !== null && ageS > feed.staleAfterS ? "stale" : "live";
}

function AccountMenu() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const { me } = useConsole();
  const { signOut } = useSession();
  const [failed, setFailed] = useState(false);
  if (me === null) return null;
  return (
    <span className="flex items-center gap-2">
      <span data-testid="account-menu" className="inline-flex">
        <UserMenu name={me.account.username} detail={t("cisp.console.account.role", { role: t(`cisp.console.role.${me.account.role}`) })}>
          <DropdownMenuItem
            onSelect={() => {
              setFailed(false);
              signOut()
                .then(() => router.replace(loginPath(lang)))
                .catch(() => setFailed(true));
            }}
          >
            <SignOutIcon />
            {t("cisp.console.account.sign_out")}
          </DropdownMenuItem>
        </UserMenu>
      </span>
      {failed && (
        <span role="alert" className="text-xs text-[var(--us-danger)]">
          {t("cisp.console.account.sign_out_failed")}
        </span>
      )}
    </span>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const { brand } = useTheme();
  const pathname = usePathname();
  const cfg = useRuntimeConfig();
  const { me, role, meFailure } = useConsole();
  const base = `/${lang}/console`;
  // The status stream (same origin, the session cookie rides the upgrade).
  const feed = useFeed({ url: `${cfg.apiBaseUrl}/v1/stream`, onFrame: () => undefined });
  const nowMs = useNowMs(TICK_MS);
  const ageS = feed.lastFrameAtMs === null ? null : Math.max(0, Math.round((nowMs - feed.lastFrameAtMs) / 1000));
  const items = navFor(role);
  const nav: NavGroup[] = GROUPS.map((g) => ({
    id: g,
    label: t(`cisp.console.nav.group.${g}`),
    items: items
      .filter((i) => PLACE[i.path]?.group === g)
      .map((i) => {
        const href = `${base}${i.path}`;
        return {
          id: i.path === "" ? "overview" : i.path.slice(1),
          label: t(i.labelKey),
          href,
          icon: PLACE[i.path]?.icon,
          active: i.path === "" ? pathname === base : pathname.startsWith(href),
        };
      }),
  })).filter((g) => g.items.length > 0);

  return (
    <AppShell
      systemName={brand.name}
      logo={<BrandMark />}
      nav={nav}
      renderLink={renderLink}
      status={me === null ? undefined : <StatusPill state={pillState(feed, ageS)} ageS={ageS} />}
      actions={<SchemeToggle />}
      user={<AccountMenu />}
      sidebarFooter={
        <Link href={`/${lang}`} className="inline-flex items-center gap-2 font-semibold text-sidebar-text no-underline hover:underline">
          <ExternalIcon />
          {t("cisp.console.nav.public_map")}
        </Link>
      }
    >
      <StatusStrip feed={me === null ? null : feed} nowMs={nowMs} />
      <div className="mx-auto grid w-full max-w-[96rem] grid-cols-[minmax(0,1fr)] gap-5 p-4 sm:p-6">
        {meFailure !== null && <ProblemNotice failure={meFailure} />}
        {me === null && meFailure === null ? <Loading /> : children}
        <p className="m-0 border-t border-border pt-3 text-xs text-muted-foreground">{t("cisp.console.read_only_notice")}</p>
      </div>
    </AppShell>
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
