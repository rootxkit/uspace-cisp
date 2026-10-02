import type { ReactNode } from "react";
import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { CSP_NONCE_HEADER } from "@rootxkit/uspace-ui/auth/server";
import { fontClassName } from "@rootxkit/uspace-ui/fonts";
import { Providers } from "@/src/components/Providers";
import { Shell } from "@/src/components/Shell";
import { branding } from "@/src/branding";
import { isLang } from "@/src/i18n/catalogues";
import { runtimeConfig } from "@/src/runtime";
import "../globals.css";

export const dynamic = "force-dynamic";

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
  return (
    <html lang={locale} className={fontClassName} suppressHydrationWarning>
      <body className="font-sans antialiased">
        <Providers lang={locale} brand={brand} nonce={nonce} config={runtimeConfig()}>
          <Shell>{children}</Shell>
        </Providers>
      </body>
    </html>
  );
}
