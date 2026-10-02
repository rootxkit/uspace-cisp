"use client";

// /<locale>/console/login: the kit's LoginForm on the BFF's /_bff/login.
// The password goes once; for an account with MFA the API answers a
// challenge and the form asks for the code (docs/PLAN.md §15 Q41 (3)).
// The API's refusals are worded here in the viewer's language by their
// slug, a lockout with the time left from Retry-After (the form also
// counts it down and keeps the button disabled until it ends).
import { useMemo } from "react";
import { useRouter } from "next/navigation";
import { BFF_LOGIN_PATH, LoginForm } from "@rootxkit/uspace-ui/auth/client";
import { retryAfterSOf, parseProblem, problemSlug } from "@rootxkit/uspace-ui/api";
import { useLang, useT, type Translate } from "@rootxkit/uspace-ui/i18n";

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
 * name; anything else passes as the API sent it.
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
    }
    if (detail === null) return res;
    const headers = new Headers(res.headers);
    headers.delete("Content-Length");
    return new Response(JSON.stringify({ ...problem, detail }), { status: res.status, statusText: res.statusText, headers });
  };
}

export function LoginPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const doFetch = useMemo(() => localisingFetch(t), [t]);
  return (
    <div className="flex flex-col gap-4 p-4">
      <p className="m-0 max-w-prose text-sm text-[var(--us-text-muted)]">{t("cisp.console.login.intro")}</p>
      <LoginForm action={BFF_LOGIN_PATH} fetch={doFetch} onSuccess={() => router.replace(`/${lang}/console`)} />
    </div>
  );
}
