"use client";

import { fmtTimeUTC, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { MAP_DATASETS, type BannerState } from "./banner";

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
      className="flex flex-wrap items-start gap-x-6 gap-y-1 border-b border-[var(--us-border)] bg-[var(--us-surface-raised)] px-4 py-2 text-xs"
    >
      <p role="status" data-testid="feed-mode" className="font-bold">
        {t(`cisp.feed.${state.mode}`)}
      </p>
      {MAP_DATASETS.map((d) => {
        const s = state.datasets[d];
        return (
          <p key={d} data-dataset={d} data-unavailable={s.unavailableSince !== null ? "true" : "false"}>
            <span className="font-bold">{t(`cisp.dataset.${d}`)}</span>{" "}
            {s.version === null
              ? t("cisp.banner.not_yet")
              : t("cisp.banner.as_of", { version: s.version, updated: fmtTimeUTC(s.updatedAt, lang) })}
            {s.stale && <span className="ms-2 text-[var(--us-danger)]">{t("cisp.banner.stale_snapshot")}</span>}
            {s.unavailableSince !== null && (
              <span role="alert" className="ms-2 font-bold text-[var(--us-danger)]">
                {t("cisp.banner.unavailable_since", { since: fmtTimeUTC(s.unavailableSince, lang, { seconds: true }) })}
              </span>
            )}
            {s.publisherStaleSince !== undefined && (
              <span className="ms-2 text-[var(--us-danger)]">
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
