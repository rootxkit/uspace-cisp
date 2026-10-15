"use client";

// The parts every frame shares: the brand mark, the scheme toggle and the
// router link the kit's frame components render their links with.
import Link from "next/link";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import type { LinkRenderer } from "@rootxkit/uspace-ui/ui";
import { MoonIcon, SunIcon } from "./icons";

/** next/link for AppShell, PageHeader and the rest, so navigation stays client-side. */
export const renderLink: LinkRenderer = (p) => <Link {...p} />;

/** The configured logo, or a neutral mark in the brand's accent. Decorative. */
export function BrandMark() {
  const { brand } = useTheme();
  if (brand.logoUrl !== null) return <img src={brand.logoUrl} alt="" className="size-7 object-contain" />;
  return (
    <svg viewBox="0 0 28 28" width="28" height="28" aria-hidden="true" focusable="false">
      <rect width="28" height="28" rx="7" fill="var(--us-brand-accent)" />
      <path
        d="M7 18.5c2.2-5.6 11.8-5.6 14 0M9.5 13c1.6-3 7.4-3 9 0"
        fill="none"
        stroke="var(--us-on-brand-accent)"
        strokeWidth="2.2"
        strokeLinecap="round"
      />
      <circle cx="14" cy="18.5" r="1.8" fill="var(--us-on-brand-accent)" />
    </svg>
  );
}

/** The dark/light switch: a pressed button, remembered in uspace_scheme (src/components/Providers). */
export function SchemeToggle() {
  const t = useT();
  const { resolved, setScheme } = useTheme();
  const dark = resolved === "dark";
  return (
    <button
      type="button"
      aria-pressed={dark}
      aria-label={t("cisp.scheme.dark")}
      onClick={() => setScheme(dark ? "light" : "dark")}
      className="inline-flex size-8 shrink-0 items-center justify-center rounded-md border border-border bg-card text-foreground transition-colors hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
    >
      {dark ? <MoonIcon /> : <SunIcon />}
    </button>
  );
}
