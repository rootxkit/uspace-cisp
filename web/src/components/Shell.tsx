"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LocaleSwitch } from "./LocaleSwitch";

/** Header, navigation and footer around every page. */
export function Shell({ children }: { children: ReactNode }) {
  const t = useT();
  const { lang } = useLang();
  const { brand } = useTheme();
  return (
    <div className="flex min-h-full flex-col">
      <a href="#main" className="sr-only focus:not-sr-only">
        {t("cisp.skip")}
      </a>
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--us-border)] bg-[var(--us-surface-raised)] px-4 py-3">
        <div className="flex items-center gap-3">
          {brand.logoUrl !== null && <img src={brand.logoUrl} alt="" className="h-8 w-auto" />}
          <div>
            <h1 className="text-lg font-bold">{t("cisp.app.title")}</h1>
            <p className="text-sm text-[var(--us-text-muted)]">{t("cisp.app.tagline")}</p>
          </div>
        </div>
        <nav aria-label={t("cisp.nav.label")} className="flex gap-4 text-sm">
          <Link href={`/${lang}`}>{t("cisp.nav.map")}</Link>
          <Link href={`/${lang}/console`}>{t("cisp.nav.console")}</Link>
        </nav>
        <LocaleSwitch />
      </header>
      <main id="main" className="flex-1">
        {children}
      </main>
      <footer className="border-t border-[var(--us-border)] px-4 py-2 text-xs text-[var(--us-text-muted)]">
        <span>{t("cisp.footer.operator", { name: brand.name })}</span>
        {brand.contact !== null && <span className="ms-4">{t("cisp.footer.contact", { contact: brand.contact })}</span>}
      </footer>
    </div>
  );
}
