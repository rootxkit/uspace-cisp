// The console's only ways to reach the API (docs/PLAN.md §1.2, §6.6):
//
// - consoleClient: the kit's typed client on the BFF's proxy
//   (/_bff/api/v1/console/*). The BFF holds the session in its HttpOnly
//   cookie and forwards it as the bearer; unsafe methods carry the
//   double-submit X-CSRF-Token. The proxy reaches /v1/console/* and
//   nothing else, and no console operation writes content.
// - previewClient: GET /public/v1/{dataset}, the public read every
//   visitor of the map makes, for the map previews of the current
//   version (docs/PLAN.md §15 Q44). Only GET is exposed.
//
// test/console-paths.test.ts reads this directory and the console pages
// and fails on any other API path.
import { BFF_API_PREFIX, csrfToken } from "@rootxkit/uspace-ui/auth/client";
import { ApiError, createClient } from "@rootxkit/uspace-ui/api";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { Problem } from "@rootxkit/uspace-ui/model";
import type { paths } from "../api/types";

/** The console's calls, all under /v1/console/ through the BFF. */
export function consoleClient(lang: () => Lang, onUnauthorized: () => void) {
  return createClient<paths>({
    baseUrl: BFF_API_PREFIX,
    csrfToken: () => csrfToken(),
    onUnauthorized,
    lang,
  });
}

export type ConsoleClient = ReturnType<typeof consoleClient>;

/** The public read of one dataset, GET only, for a map preview. */
export function previewClient(apiBaseUrl: string, lang: () => Lang) {
  const c = createClient<paths>({ baseUrl: apiBaseUrl, lang });
  return { GET: c.GET.bind(c) };
}

/** What a refused or failed call said, for ProblemNotice. */
export interface CallFailure {
  /** The HTTP status; 0 when the API could not be reached. */
  status: number;
  problem: Problem | null;
  /** The problem's slug (`forbidden`, `not_found`, ...), or null. */
  slug: string | null;
  retryAfterS: number | null;
}

/** A rejection of the kit's client as a CallFailure. */
export function failureOf(err: unknown): CallFailure {
  if (err instanceof ApiError) {
    return { status: err.status, problem: err.problem, slug: err.slug, retryAfterS: err.retryAfterS };
  }
  return { status: 0, problem: null, slug: null, retryAfterS: null };
}
