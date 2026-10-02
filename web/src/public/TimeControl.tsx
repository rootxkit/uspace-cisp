"use client";

import { useId } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";

export type TimeChoice = { kind: "now" } | { kind: "instant"; local: string };

/** The instant a datetime-local value names in this browser's zone, as RFC 3339 UTC; null if invalid. */
export function instantOf(local: string): string | null {
  if (local === "") return null;
  const ms = new Date(local).getTime();
  return Number.isFinite(ms) ? new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z") : null;
}

/**
 * "Show zones applicable at now | a chosen instant": the map asks the
 * CISP to annotate every feature at that instant (applies_at) and dims
 * what does not apply. Nothing is filtered out.
 */
export function TimeControl(props: { value: TimeChoice; onChange(v: TimeChoice): void; instantShown: string }) {
  const t = useT();
  const id = useId();
  const { value, onChange } = props;
  return (
    <fieldset className="flex flex-col gap-2 text-sm">
      <legend className="font-bold">{t("cisp.time.legend")}</legend>
      <label className="flex items-center gap-2">
        <input type="radio" name={`${id}-when`} checked={value.kind === "now"} onChange={() => onChange({ kind: "now" })} />
        {t("cisp.time.now")}
      </label>
      <label className="flex flex-wrap items-center gap-2">
        <input
          type="radio"
          name={`${id}-when`}
          checked={value.kind === "instant"}
          onChange={() => onChange({ kind: "instant", local: value.kind === "instant" ? value.local : "" })}
        />
        {t("cisp.time.instant")}
        <input
          type="datetime-local"
          aria-label={t("cisp.time.instant_input")}
          className="rounded border border-[var(--us-border)] bg-[var(--us-surface-raised)] px-2 py-1"
          value={value.kind === "instant" ? value.local : ""}
          onChange={(e) => onChange({ kind: "instant", local: e.target.value })}
        />
      </label>
      <p className="text-xs text-[var(--us-text-muted)]">{t("cisp.time.asked", { instant: props.instantShown })}</p>
    </fieldset>
  );
}
