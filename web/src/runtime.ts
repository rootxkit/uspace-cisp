// Values the server reads at request time and hands to the page. They
// are read with bracket access so `next build` does not inline them: the
// image is built once in CI and configured at start.
export interface RuntimeConfig {
  /** Where the browser reaches the API; "" is same-origin (NEXT_PUBLIC_API_BASE_URL). */
  apiBaseUrl: string;
}

export function runtimeConfig(): RuntimeConfig {
  return { apiBaseUrl: process.env["NEXT_PUBLIC_API_BASE_URL"] ?? "" };
}
