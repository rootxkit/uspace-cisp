import type { ReactNode } from "react";
import { cookies, headers } from "next/headers";
import { notFound } from "next/navigation";
import { CSP_NONCE_HEADER } from "@rootxkit/uspace-ui/auth/server";
import { fontClassName } from "@rootxkit/uspace-ui/fonts";
import { SCHEME_COOKIE, parseScheme, schemeAttribute } from "@rootxkit/uspace-ui/theme";
import { Providers } from "@/src/components/Providers";
import { branding } from "@/src/branding";
import { isLang } from "@/src/i18n/catalogues";
import { layoutMetadata } from "@/src/i18n/metadata";
import { runtimeConfig } from "@/src/runtime";
import "../globals.css";

export const dynamic = "force-dynamic";

export const generateMetadata = layoutMetadata;

// Every page: the language from the address, the nonce, the brand. The
// frame is the route group's: the public pages' top bar ((public)/layout),
// the sign-in's (console/login) and the signed-in console's AppShell
// ((signed-in)/layout).
export default async function LocaleLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  if (!isLang(locale)) notFound();
  const nonce = (await headers()).get(CSP_NONCE_HEADER) ?? undefined;
  const brand = branding();
  // An explicit scheme is painted from the first byte; none (or system)
  // leaves data-theme off and the kit's tokens follow the preference.
  const scheme = parseScheme((await cookies()).get(SCHEME_COOKIE)?.value);
  return (
    <html lang={locale} className={fontClassName} data-theme={schemeAttribute(scheme)} suppressHydrationWarning>
      <body className="font-sans antialiased">
        <Providers lang={locale} brand={brand} nonce={nonce} config={runtimeConfig()} {...(scheme === null ? {} : { scheme })}>
          {children}
        </Providers>
      </body>
    </html>
  );
}
