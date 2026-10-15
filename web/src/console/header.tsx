"use client";

// The top of every console page: the kit's PageHeader with the trail
// from the console's root, the page's h1, its description and actions.
import type { ReactNode } from "react";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { PageHeader, type Crumb } from "@rootxkit/uspace-ui/ui";
import { renderLink } from "../components/frame";

export function ConsoleHeader(props: {
  title: ReactNode;
  description?: ReactNode;
  /** Steps between the console's root and this page. */
  trail?: readonly Crumb[];
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  const t = useT();
  const { lang } = useLang();
  const breadcrumbs: Crumb[] = [{ label: t("cisp.nav.console"), href: `/${lang}/console` }, ...(props.trail ?? []), { label: props.title }];
  return (
    <PageHeader
      title={props.title}
      breadcrumbs={breadcrumbs}
      renderLink={renderLink}
      {...(props.description === undefined ? {} : { description: props.description })}
      {...(props.actions === undefined ? {} : { actions: props.actions })}
      {...(props.meta === undefined ? {} : { meta: props.meta })}
    />
  );
}
