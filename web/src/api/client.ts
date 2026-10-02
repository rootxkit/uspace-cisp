// A thin typed client over the kit's openapi-fetch adapter. The browser
// reaches the API at the configured public base (NEXT_PUBLIC_API_BASE_URL,
// handed down by the server at request time; "" is same-origin); server
// code reaches it at CISP_API_INTERNAL_URL.
import { createClient, type Client } from "@rootxkit/uspace-ui/api";
import type { Lang } from "@rootxkit/uspace-ui/i18n";
import type { paths } from "./types";

export type CispClient = Client<paths>;

/** The client a page uses in the browser. */
export function browserClient(apiBaseUrl: string, lang: () => Lang): CispClient {
  return createClient<paths>({ baseUrl: apiBaseUrl, lang });
}

/** The client server code uses; null when CISP_API_INTERNAL_URL is unset. */
export function serverClient(): CispClient | null {
  const base = process.env["CISP_API_INTERNAL_URL"];
  return base === undefined || base === "" ? null : createClient<paths>({ baseUrl: base });
}
