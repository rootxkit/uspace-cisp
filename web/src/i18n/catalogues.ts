// The app's own ka/en catalogues, handed to the kit's I18nProvider (which
// puts them ahead of the kit's). Every display string in app/ comes from
// here or from the kit (CLAUDE.md rule 9).
import type { Catalogues, Lang } from "@rootxkit/uspace-ui/i18n";
import en from "./en.json";
import ka from "./ka.json";

export const catalogues: Catalogues = { ka, en };

export type AppKey = keyof typeof en;

export function isLang(v: string): v is Lang {
  return v === "ka" || v === "en";
}
