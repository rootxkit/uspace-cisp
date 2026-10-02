"use client";

// One version: what it added, changed (with the paths) and removed
// against its predecessor (GET /v1/console/publications/{id}/diff), a
// map preview of the features it touched when it is still the current
// version, and the republish action on the current version.
import { useState } from "react";
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button } from "@rootxkit/uspace-ui/ui";
import { useLoad } from "./context";
import { anythingHidden, diffView, PATHS_SHOWN, type FeatureRow, type PathChange, type PublicationDiff } from "./diff";
import { FeaturePreview, isMapDataset } from "./FeaturePreview";
import { isDataset, reasonLabel, RepublishAction } from "./PublicationsPage";
import { Loading, ProblemNotice, Section, Time } from "./ui";

function Paths({ paths, hidden, truncatedByApi }: { paths: PathChange[]; hidden: number; truncatedByApi: boolean }) {
  const t = useT();
  return (
    <>
      <ul className="m-0 ps-5 text-xs" data-testid="diff-paths">
        {paths.map((p, i) => (
          <li key={`${p.path}-${i}`}>
            <code>{p.path === "" ? "/" : p.path}</code> <span className="text-[var(--us-text-muted)]">{t(`cisp.console.diff.op.${p.op}`)}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <p className="m-0 text-xs" data-testid="paths-hidden">
          {t("cisp.console.diff.paths_hidden", { count: hidden })}
        </p>
      )}
      {truncatedByApi && (
        <p className="m-0 text-xs font-semibold" data-testid="paths-truncated">
          {t("cisp.console.diff.paths_truncated")}
        </p>
      )}
    </>
  );
}

function Group({ titleKey, rows }: { titleKey: string; rows: FeatureRow[] }) {
  const t = useT();
  return (
    <Section titleKey={titleKey} vars={{ count: rows.length }}>
      {rows.length === 0 ? (
        <p className="m-0 text-sm text-[var(--us-text-muted)]">{t("cisp.console.diff.none")}</p>
      ) : (
        <ul className="m-0 flex flex-col gap-2 ps-0">
          {rows.map((r) => (
            <li key={`${r.op}-${r.featureId}`} className="list-none" data-feature={r.featureId} data-op={r.op}>
              <span className="font-mono font-semibold">{r.featureId}</span>
              {r.op === "changed" && <Paths paths={r.paths} hidden={r.hiddenPaths} truncatedByApi={r.pathsTruncatedByApi} />}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export function DiffBody({ diff }: { diff: PublicationDiff }) {
  const t = useT();
  const [all, setAll] = useState(false);
  const v = diffView(diff, all ? Number.POSITIVE_INFINITY : PATHS_SHOWN);
  return (
    <div className="flex flex-col gap-3" data-testid="diff">
      <p className="m-0 text-sm">
        {v.previousVersion === null
          ? t("cisp.console.diff.first_version")
          : t("cisp.console.diff.against", { version: v.previousVersion })}
      </p>
      {v.featuresTruncated && (
        <p role="note" className="m-0 text-sm font-semibold" data-testid="features-truncated">
          {t("cisp.console.diff.features_truncated", { count: diff.features.length })}
        </p>
      )}
      <Group titleKey="cisp.console.diff.added" rows={v.added} />
      <Group titleKey="cisp.console.diff.changed" rows={v.changed} />
      <Group titleKey="cisp.console.diff.removed" rows={v.removed} />
      {(diff.body_paths !== undefined || v.bodyPathsTruncatedByApi) && (
        <Section titleKey="cisp.console.diff.body_paths">
          <Paths paths={v.bodyPaths} hidden={v.hiddenBodyPaths} truncatedByApi={v.bodyPathsTruncatedByApi} />
        </Section>
      )}
      {!all && anythingHidden(v) && (v.hiddenBodyPaths > 0 || [...v.changed].some((r) => r.hiddenPaths > 0)) && (
        <div>
          <Button type="button" size="sm" variant="outline" onClick={() => setAll(true)}>
            {t("cisp.console.diff.show_all")}
          </Button>
        </div>
      )}
    </div>
  );
}

export function VersionPage({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const diff = useLoad(
    async (c) => (await c.GET("/v1/console/publications/{id}/diff", { params: { path: { id } } })).data ?? null,
    id,
  );
  const dataset = diff.data?.publication.dataset ?? null;
  // The dataset's current version: the newest of its list.
  const current = useLoad(
    async (c) =>
      !isDataset(dataset)
        ? null
        : ((await c.GET("/v1/console/publications", { params: { query: { dataset, limit: 1 } } })).data?.versions[0] ?? null),
    `${dataset ?? ""}:${diff.data?.publication.id ?? ""}`,
  );
  const p = diff.data?.publication;
  const isCurrent = p !== undefined && current.data !== null && current.data.id === p.id;
  const touched = diff.data?.features.filter((f) => f.op !== "removed").map((f) => f.feature_id) ?? [];
  return (
    <div className="flex flex-col gap-4">
      <Link href={`/${lang}/console/publications${dataset === null ? "" : `?dataset=${dataset}`}`} className="text-sm underline">
        {t("cisp.console.publications.back")}
      </Link>
      {diff.failure !== null && <ProblemNotice failure={diff.failure} />}
      {diff.loading && diff.data === null && <Loading />}
      {p !== undefined && diff.data !== null && (
        <>
          <h2 className="m-0 text-lg font-bold">
            {t("cisp.console.version.title", { dataset: t(`cisp.console.dataset.${p.dataset}`), version: p.version })}
          </h2>
          <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt>{t("cisp.console.publications.received")}</dt>
            <dd className="m-0">
              <Time iso={p.received_at} />
            </dd>
            <dt>{t("cisp.console.publications.publisher")}</dt>
            <dd className="m-0">{p.publisher}</dd>
            <dt>{t("cisp.console.publications.reason")}</dt>
            <dd className="m-0">{reasonLabel(t, p.reason)}</dd>
            <dt>{t("cisp.console.publications.counts")}</dt>
            <dd className="m-0">
              {t("cisp.console.publications.counts_value", {
                features: p.feature_count,
                added: p.added,
                changed: p.changed,
                removed: p.removed,
              })}
            </dd>
            <dt>{t("cisp.console.version.state")}</dt>
            <dd className="m-0" data-testid="version-current">
              {current.data === null
                ? "—"
                : isCurrent
                  ? t("cisp.console.publications.current")
                  : t("cisp.console.version.superseded", { version: current.data.version })}
            </dd>
          </dl>
          {isCurrent && <RepublishAction version={p} onDone={current.reload} />}
          <DiffBody diff={diff.data} />
          {isMapDataset(p.dataset) && touched.length > 0 && (
            <Section titleKey="cisp.console.preview.title">
              {isCurrent ? (
                <FeaturePreview dataset={p.dataset} ids={touched} />
              ) : (
                <p className="m-0 text-sm">{t("cisp.console.preview.not_current")}</p>
              )}
            </Section>
          )}
        </>
      )}
    </div>
  );
}
