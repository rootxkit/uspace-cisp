"use client";

import { createContext, useCallback, useContext, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { I18nProvider, LANG_COOKIE, type Lang } from "@rootxkit/uspace-ui/i18n";
import { SCHEME_COOKIE, ThemeProvider, type Brand, type ColorScheme } from "@rootxkit/uspace-ui/theme";
import { CspNonceProvider } from "@rootxkit/uspace-ui/ui";
import { catalogues } from "../i18n/catalogues";
import type { RuntimeConfig } from "../runtime";

const RuntimeContext = createContext<RuntimeConfig | null>(null);

/** How long a viewer's language and scheme choices are remembered. Display-only. */
const CHOICE_MAX_AGE_S = 31_536_000;

/** The request-time configuration the server handed to the page. */
export function useRuntimeConfig(): RuntimeConfig {
  const v = useContext(RuntimeContext);
  if (v === null) throw new Error("useRuntimeConfig outside Providers");
  return v;
}

/** `pathname` under the prefix of `lang` (/ka/..., /en/...). */
export function pathInLang(pathname: string, lang: Lang): string {
  return `/${lang}${pathname.replace(/^\/(ka|en)(?=\/|$)/, "")}`;
}

function remember(name: string, value: string): void {
  document.cookie = `${name}=${value}; Path=/; Max-Age=${String(CHOICE_MAX_AGE_S)}; SameSite=Lax`;
}

export function Providers(props: {
  lang: Lang;
  brand: Brand;
  nonce: string | undefined;
  config: RuntimeConfig;
  /** The scheme the server read from uspace_scheme; absent follows the system. */
  scheme?: ColorScheme;
  children: ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  // The language lives in the address: the kit's switch moves to the same
  // page under the other prefix, keeping its query, and remembers the
  // choice in uspace_lang for the root's redirect.
  const onLangChange = useCallback(
    (l: Lang) => {
      remember(LANG_COOKIE, l);
      router.push(`${pathInLang(pathname, l)}${window.location.search}`);
    },
    [router, pathname],
  );
  const onSchemeChange = useCallback((s: ColorScheme) => remember(SCHEME_COOKIE, s), []);
  return (
    <CspNonceProvider nonce={props.nonce}>
      <RuntimeContext.Provider value={props.config}>
        <ThemeProvider brand={props.brand} onSchemeChange={onSchemeChange} {...(props.scheme === undefined ? {} : { scheme: props.scheme })}>
          <I18nProvider lang={props.lang} catalogues={catalogues} onLangChange={onLangChange}>
            {props.children}
          </I18nProvider>
        </ThemeProvider>
      </RuntimeContext.Provider>
    </CspNonceProvider>
  );
}
