"use client";

import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import type { StatusTone } from "@rootxkit/uspace-ui/theme";
import { StatusBadge } from "@rootxkit/uspace-ui/ui";
import { MAP_DATASETS, type BannerState, type FeedMode } from "./banner";

/** The tone that repeats each feed mode's words. Display-only. */
const MODE_TONE: Record<FeedMode, StatusTone> = {
  connecting: "info",
  live: "ok",
  polling: "warning",
  disconnected: "critical",
};

/**
 * Per dataset the version and update time the map shows (Art. 9(2)), the
 * ANSP's staleness, "unavailable since" when the API cannot serve it, and
 * how changes reach the page: live, polling, or disconnected.
 */
export function AsOfBanner({ state }: { state: BannerState }) {
  const t = useT();
  const { lang } = useLang();
  return (
    <section
      aria-label={t("cisp.banner.label")}
      data-feed={state.mode}
      className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-panel border border-border bg-card px-4 py-2.5 text-xs text-card-foreground shadow-panel"
    >
      <StatusBadge role="status" data-testid="feed-mode" tone={MODE_TONE[state.mode]}>
        {t(`cisp.feed.${state.mode}`)}
      </StatusBadge>
      {MAP_DATASETS.map((d) => {
        const s = state.datasets[d];
        return (
          <p key={d} data-dataset={d} data-unavailable={s.unavailableSince !== null ? "true" : "false"} className="m-0">
            <span className="font-semibold">{t(`cisp.dataset.${d}`)}</span>{" "}
            <span className="text-muted-foreground">
              {s.version === null
                ? t("cisp.banner.not_yet")
                : t("cisp.banner.as_of", { version: s.version, updated: fmtTimeUTC(s.updatedAt, lang) })}
            </span>
            {s.stale && <span className="ms-2 font-semibold text-[var(--us-danger)]">{t("cisp.banner.stale_snapshot")}</span>}
            {s.unavailableSince !== null && (
              <span role="alert" className="ms-2 font-bold text-[var(--us-danger)]">
                {t("cisp.banner.unavailable_since", { since: fmtTimeUTC(s.unavailableSince, lang, { seconds: true }) })}
              </span>
            )}
            {s.publisherStaleSince !== undefined && (
              <span className="ms-2 font-semibold text-[var(--us-danger)]">
                {s.publisherStaleSince === null
                  ? t("cisp.banner.publisher_never_heard")
                  : t("cisp.banner.publisher_stale_since", { since: fmtTimeUTC(s.publisherStaleSince, lang) })}
              </span>
            )}
          </p>
        );
      })}
    </section>
  );
}
