"use client";

// Publications: per dataset the version list, newest first (GET
// /v1/console/publications), paged with `before`. The current version
// carries the publisher_admin action "republish current version", which
// announces the version again and changes no content (docs/PLAN.md §15
// Q13). Warnings, the signature kid and the refused attempts are not
// served by the console API (Q44); the page says so instead of leaving
// the columns out silently.
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { useConsole, useLoad, type Loaded } from "./context";
import { mayAct } from "./roles";
import { Loading, ProblemNotice, ReasonAction, Time } from "./ui";

export const DATASETS = ["zones", "uspace_airspace", "restrictions", "ussp_list"] as const;
export type Dataset = (typeof DATASETS)[number];
type Version = components["schemas"]["ConsolePublicationVersion"];
type VersionList = components["schemas"]["ConsolePublicationList"];

/** The change reasons the console words (Change.reason); another is shown as sent. */
export const REASONS = [
  "publication",
  "restriction_created",
  "restriction_activated",
  "restriction_extended",
  "restriction_ended",
  "restriction_cancelled",
  "restriction_expired",
  "republished",
  "subscription_test",
] as const;

export function reasonLabel(t: (k: string) => string, reason: string): string {
  return (REASONS as readonly string[]).includes(reason) ? t(`cisp.console.reason.${reason}`) : reason;
}

export function isDataset(v: string | null): v is Dataset {
  return v !== null && (DATASETS as readonly string[]).includes(v);
}

/** The republish action for the current version of a dataset. */
export function RepublishAction({ version, onDone }: { version: Version; onDone?(): void }) {
  const { client, role } = useConsole();
  if (!mayAct(role, "republish")) return null;
  return (
    <ReasonAction
      testId={`republish-${version.dataset}-${version.version}`}
      labelKey="cisp.console.publications.republish"
      titleKey="cisp.console.publications.republish_title"
      bodyKey="cisp.console.publications.republish_body"
      doneKey="cisp.console.publications.republished"
      vars={{ version: version.version, dataset: version.dataset }}
      act={(reason) =>
        client.POST("/v1/console/publications/{id}/republish", { params: { path: { id: version.id } }, body: { reason } })
      }
      {...(onDone === undefined ? {} : { onDone })}
    />
  );
}

function VersionTable({ list, isFirstPage, reload }: { list: VersionList; isFirstPage: boolean; reload(): void }) {
  const t = useT();
  const { lang } = useLang();
  if (list.versions.length === 0) return <p className="m-0 text-sm">{t("cisp.console.publications.none")}</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{t("cisp.console.publications.version")}</TableHead>
          <TableHead>{t("cisp.console.publications.received")}</TableHead>
          <TableHead>{t("cisp.console.publications.publisher")}</TableHead>
          <TableHead>{t("cisp.console.publications.counts")}</TableHead>
          <TableHead>{t("cisp.console.publications.reason")}</TableHead>
          <TableHead>{t("cisp.console.publications.actions")}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {list.versions.map((v, i) => (
          <TableRow key={v.id} data-version={v.version}>
            <TableCell>
              <Link href={`/${lang}/console/publications/${encodeURIComponent(v.id)}`} className="underline">
                {t("cisp.console.publications.version_n", { version: v.version })}
              </Link>
              {isFirstPage && i === 0 && <span className="ms-2 text-xs font-semibold">{t("cisp.console.publications.current")}</span>}
            </TableCell>
            <TableCell>
              <Time iso={v.received_at} />
            </TableCell>
            <TableCell>{v.publisher}</TableCell>
            <TableCell>
              {t("cisp.console.publications.counts_value", {
                features: v.feature_count,
                added: v.added,
                changed: v.changed,
                removed: v.removed,
              })}
            </TableCell>
            <TableCell>{reasonLabel(t, v.reason)}</TableCell>
            <TableCell>{isFirstPage && i === 0 && <RepublishAction version={v} onDone={reload} />}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function PublicationsPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const params = useSearchParams();
  const raw = params.get("dataset");
  const dataset: Dataset = isDataset(raw) ? raw : "zones";
  const beforeRaw = Number(params.get("before"));
  const before = Number.isInteger(beforeRaw) && beforeRaw >= 1 ? beforeRaw : undefined;
  const list: Loaded<VersionList | null> = useLoad(
    async (c) =>
      (
        await c.GET("/v1/console/publications", {
          params: { query: { dataset, ...(before === undefined ? {} : { before }) } },
        })
      ).data ?? null,
    `${dataset}:${before ?? ""}`,
  );
  const base = `/${lang}/console/publications`;
  return (
    <div className="flex flex-col gap-3">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.publications")}</h2>
      <nav aria-label={t("cisp.console.publications.datasets")} className="flex flex-wrap gap-2">
        {DATASETS.map((d) => (
          <Link
            key={d}
            href={`${base}?dataset=${d}`}
            aria-current={d === dataset ? "page" : undefined}
            className={`rounded border px-2 py-1 text-sm ${d === dataset ? "border-[var(--us-border-strong)] font-bold" : "border-[var(--us-border)]"}`}
          >
            {t(`cisp.console.dataset.${d}`)}
          </Link>
        ))}
      </nav>
      <p className="m-0 text-xs text-[var(--us-text-muted)]">{t("cisp.console.publications.not_served")}</p>
      {list.failure !== null && <ProblemNotice failure={list.failure} />}
      {list.loading && list.data === null && <Loading />}
      {list.data !== null && <VersionTable list={list.data} isFirstPage={before === undefined} reload={list.reload} />}
      <div className="flex gap-2">
        {before !== undefined && (
          <Button type="button" variant="outline" size="sm" onClick={() => router.push(`${base}?dataset=${dataset}`)}>
            {t("cisp.console.paging.newest")}
          </Button>
        )}
        {list.data?.next_before !== undefined && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => router.push(`${base}?dataset=${dataset}&before=${list.data?.next_before ?? ""}`)}
          >
            {t("cisp.console.paging.older")}
          </Button>
        )}
      </div>
    </div>
  );
}
