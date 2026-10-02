"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LANG_COOKIE, LANGS, useLang, useT } from "@rootxkit/uspace-ui/i18n";

/** The same page in the other language; remembers the choice in uspace_lang. */
export function LocaleSwitch() {
  const t = useT();
  const { lang } = useLang();
  const pathname = usePathname();
  const rest = pathname.replace(/^\/(ka|en)(?=\/|$)/, "");
  return (
    <nav aria-label={t("cisp.locale.label")} className="flex gap-2 text-sm">
      {LANGS.map((l) =>
        l === lang ? (
          <span key={l} aria-current="true" className="font-bold">
            {t(`cisp.locale.${l}`)}
          </span>
        ) : (
          <Link
            key={l}
            href={`/${l}${rest}`}
            hrefLang={l}
            lang={l}
            className="underline underline-offset-2"
            onClick={() => {
              document.cookie = `${LANG_COOKIE}=${l}; Path=/; Max-Age=31536000; SameSite=Lax`;
            }}
          >
            {t(`cisp.locale.${l}`)}
          </Link>
        ),
      )}
    </nav>
  );
}
