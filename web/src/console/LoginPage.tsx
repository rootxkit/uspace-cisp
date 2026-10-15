"use client";

// /<locale>/console/login: the kit's LoginForm on the BFF's /_bff/login.
// The password goes once; for an account with MFA the API answers a
// challenge and the form asks for the code (docs/PLAN.md §15 Q41 (3)).
// The API's refusals are worded here in the viewer's language by their
// slug, a lockout with the time left from Retry-After (the form also
// counts it down and keeps the button disabled until it ends), a refused
// field by what it takes (src/console/validation.ts), and anything else
// by its status: the API's English never reaches the form.
import { useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { BFF_LOGIN_PATH, LoginForm } from "@rootxkit/uspace-ui/auth/client";
import { retryAfterSOf, parseProblem, problemSlug } from "@rootxkit/uspace-ui/api";
import { useLang, useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { useTheme } from "@rootxkit/uspace-ui/theme";
import { LanguageSwitch, PageHeader, Panel } from "@rootxkit/uspace-ui/ui";
import { BrandMark, SchemeToggle } from "../components/frame";
import { LockIcon } from "../components/icons";
import { fieldMessages, fieldSentence } from "./validation";

/** The login refusals the console words itself (the API's slugs). */
export const LOGIN_SLUGS = [
  "invalid_credentials",
  "invalid_totp",
  "totp_reused",
  "mfa_required",
  "challenge_invalid",
  "mfa_challenge_missing",
  "rate_limited",
  "busy",
  "console_unavailable",
  "bff_unavailable",
] as const;

/** Whole minutes left of a lockout, at least 1. */
export function minutesLeft(retryAfterS: number): number {
  return Math.max(1, Math.ceil(retryAfterS / 60));
}

/**
 * A fetch for the form that rewrites the problem body's `detail` into the
 * viewer's language: the lockout with its time left, the known slugs by
 * name, a refused field (400) by what the field takes, and any other
 * refusal by its status. Only a success passes untouched.
 */
export function localisingFetch(t: Translate, base: typeof fetch = fetch): typeof fetch {
  return async (input, init) => {
    const res = await base(input, init);
    if (res.ok) return res;
    const problem = await parseProblem(res.clone());
    if (problem === null) return res;
    const slug = problemSlug(problem.type);
    let detail: string | null = null;
    if (res.status === 423 || slug === "locked") {
      const wait = retryAfterSOf(res.headers.get("Retry-After"), Date.now());
      detail =
        wait === null || wait <= 0
          ? t("cisp.console.login.locked")
          : t("cisp.console.login.locked_for", { minutes: minutesLeft(wait) });
    } else if (slug !== null && (LOGIN_SLUGS as readonly string[]).includes(slug)) {
      detail = t(`cisp.console.login.problem.${slug}`);
    } else {
      const fields = fieldMessages(t, res.status, slug, problem);
      detail = fields === null ? t("cisp.console.problem.refused", { status: res.status }) : fieldSentence(fields);
    }
    const headers = new Headers(res.headers);
    headers.delete("Content-Length");
    return new Response(JSON.stringify({ ...problem, detail }), { status: res.status, statusText: res.statusText, headers });
  };
}

export function LoginPage() {
  const t = useT();
  const { lang } = useLang();
  const { brand } = useTheme();
  const router = useRouter();
  const doFetch = useMemo(() => localisingFetch(t), [t]);
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:shadow-overlay"
      >
        {t("cisp.skip")}
      </a>
      <header className="flex min-h-[var(--us-topbar-height)] flex-wrap items-center gap-3 border-b border-border bg-topbar px-4 py-2 sm:px-5">
        <span className="flex min-w-0 items-center gap-2.5">
          <span aria-hidden="true" className="inline-flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md">
            <BrandMark />
          </span>
          <span className="min-w-0 truncate text-sm font-bold">{brand.name}</span>
        </span>
        <span className="ms-auto flex items-center gap-2">
          <SchemeToggle />
          <LanguageSwitch />
        </span>
      </header>
      <main id="main" tabIndex={-1} className="flex flex-1 items-start justify-center px-4 py-10 outline-none sm:items-center">
        <div className="grid w-full max-w-md gap-5">
          <div className="flex items-center gap-3">
            <span aria-hidden="true" className="inline-flex size-10 items-center justify-center rounded-lg bg-accent-soft text-accent-text">
              <LockIcon />
            </span>
            <PageHeader title={t("cisp.console.login.title")} description={t("cisp.console.login.intro")} />
          </div>
          <Panel>
            <LoginForm action={BFF_LOGIN_PATH} fetch={doFetch} onSuccess={() => router.replace(`/${lang}/console`)} />
          </Panel>
          <Link href={`/${lang}`} className="justify-self-start text-sm font-semibold text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
            {t("cisp.console.login.back")}
          </Link>
        </div>
      </main>
    </div>
  );
}
