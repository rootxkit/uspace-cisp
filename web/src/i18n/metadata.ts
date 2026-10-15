// Document titles in the page's language (WCAG 2.4.2 Page Titled): the
// layout's default and template, and each page's own name, read from the
// catalogues by the [locale] param.
import type { Metadata } from "next";
import { catalogues, isLang } from "./catalogues";

type Params = { params: Promise<{ locale: string }> };

function word(locale: string, key: string): string | undefined {
  return isLang(locale) ? catalogues[locale]?.[key] : undefined;
}

/** The layout's title: the service's name, and "<page> · <service>" for a page that names itself. */
export async function layoutMetadata({ params }: Params): Promise<Metadata> {
  const app = word((await params).locale, "cisp.app.title");
  return app === undefined ? {} : { title: { default: app, template: `%s · ${app}` } };
}

/** A page's generateMetadata: its title is the catalogue's `key`. */
export function titled(key: string): (p: Params) => Promise<Metadata> {
  return async ({ params }) => {
    const title = word((await params).locale, key);
    return title === undefined ? {} : { title };
  };
}
