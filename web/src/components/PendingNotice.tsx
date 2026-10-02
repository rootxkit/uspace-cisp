"use client";

import { useT } from "@rootxkit/uspace-ui/i18n";
import type { AppKey } from "../i18n/catalogues";

/** A page this work package leaves to a later one. */
export function PendingNotice({ messageKey }: { messageKey: AppKey }) {
  const t = useT();
  return <p className="p-4 text-[var(--us-text-muted)]">{t(messageKey)}</p>;
}
