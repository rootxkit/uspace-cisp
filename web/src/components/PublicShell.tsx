"use client";

// The public pages' frame: open to everyone, no sign-in and no sidebar.
// A top bar with the brand, the public navigation (the map, the USSP
// list, the console's sign-in), the scheme toggle and the language
// switch; the page; the operator's footer.
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LanguageSwitch } from "@rootxkit/uspace-ui/ui";
import { BrandMark, SchemeToggle } from "./frame";

const NAV_LINK =
  "inline-flex h-8 items-center rounded-md px-2.5 text-sm font-semibold text-muted-foreground no-underline transition-colors hover:bg-hover hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none aria-[current=page]:bg-accent-soft aria-[current=page]:text-accent-text";

export function PublicShell({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const { brand } = useTheme();
  const pathname = usePathname();
  const items = [
    { href: `/${lang}`, key: "cisp.nav.map" },
    { href: `/${lang}/ussps`, key: "cisp.nav.ussps" },
    { href: `/${lang}/console`, key: "cisp.public.nav.signin" },
  ];
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:shadow-overlay"
      >
        {t("cisp.skip")}
      </a>
      <header
        data-part="public-topbar"
        className="sticky top-0 z-30 flex min-h-[var(--us-topbar-height)] flex-wrap items-center gap-x-4 gap-y-2 border-b border-border bg-topbar px-4 py-2 sm:px-5"
      >
        <Link href={`/${lang}`} className="flex min-w-0 items-center gap-2.5 rounded-md text-foreground no-underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
          <span aria-hidden="true" className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
            <BrandMark />
          </span>
          <span className="min-w-0 truncate text-sm font-bold">{brand.name}</span>
        </Link>
        <nav aria-label={t("cisp.nav.label")} className="order-last w-full sm:order-none sm:w-auto">
          <ul className="m-0 flex list-none flex-wrap gap-1 p-0">
            {items.map((i) => (
              <li key={i.href}>
                <Link href={i.href} aria-current={pathname === i.href ? "page" : undefined} className={NAV_LINK}>
                  {t(i.key)}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <div className="ms-auto flex items-center gap-2">
          <SchemeToggle />
          <LanguageSwitch />
        </div>
      </header>
      <main id="main" tabIndex={-1} className="flex min-w-0 flex-1 flex-col outline-none">
        {children}
      </main>
      <footer className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border bg-topbar px-4 py-2 text-xs text-muted-foreground sm:px-5">
        <span>{t("cisp.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span>{t("cisp.footer.contact", { contact: brand.contact })}</span>}
      </footer>
    </div>
  );
}
