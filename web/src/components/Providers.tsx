"use client";

import { createContext, useContext, type ReactNode } from "react";
import { I18nProvider, type Lang } from "@rootxkit/uspace-ui/i18n";
import { ThemeProvider, type Brand } from "@rootxkit/uspace-ui/theme";
import { CspNonceProvider } from "@rootxkit/uspace-ui/ui";
import { catalogues } from "../i18n/catalogues";
import type { RuntimeConfig } from "../runtime";

const RuntimeContext = createContext<RuntimeConfig | null>(null);

/** The request-time configuration the server handed to the page. */
export function useRuntimeConfig(): RuntimeConfig {
  const v = useContext(RuntimeContext);
  if (v === null) throw new Error("useRuntimeConfig outside Providers");
  return v;
}

export function Providers(props: {
  lang: Lang;
  brand: Brand;
  nonce: string | undefined;
  config: RuntimeConfig;
  children: ReactNode;
}) {
  return (
    <CspNonceProvider nonce={props.nonce}>
      <RuntimeContext.Provider value={props.config}>
        <ThemeProvider brand={props.brand}>
          <I18nProvider lang={props.lang} catalogues={catalogues}>
            {props.children}
          </I18nProvider>
        </ThemeProvider>
      </RuntimeContext.Provider>
    </CspNonceProvider>
  );
}
