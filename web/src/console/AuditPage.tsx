"use client";

// Audit (admin): the events table (GET /v1/console/audit), newest first,
// filtered by since, actor and type, paged with before_id. A row shows
// the event's number, its time in UTC, the actor (by username where the
// accounts list has it) and the event's label; its entity, hashes and
// payload are behind the row's expander. The since filter is typed as a
// UTC wall clock (the kit's UTC box, inputToUtc), and its label says so.
import { useState } from "react";
import { useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { Button, Input, Label, StatusBadge, TABLE_NOWRAP, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, cn } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { useLoad } from "./context";
import { ConsoleHeader } from "./header";
import { eventLabel, payloadKeyLabel } from "./labels";
import { CopyId, DetailsRow, ExpandCell, Facts, ShortId, useExpander } from "./present";
import { Loading, TablePanel, ProblemNotice, Time } from "./ui";

type AuditEvent = components["schemas"]["ConsoleAuditEvent"];

const DATASET_NAMES: readonly string[] = ["zones", "uspace_airspace", "restrictions", "ussp_list"];

/** A payload member's value on one line: text as sent (a dataset by its label), anything else as compact JSON. */
export function payloadValue(t: Translate, member: string, v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return member === "dataset" && DATASET_NAMES.includes(v) ? t(`cisp.console.dataset.${v}`) : v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

/** The actor: an account by its username where the accounts list has it, else its id (short when long). */
function Actor({ e, usernames }: { e: AuditEvent; usernames: ReadonlyMap<string, string> }) {
  const t = useT();
  const username = e.actor_type === "account" ? usernames.get(e.actor_id) : undefined;
  return (
    <div className="flex min-w-0 flex-col" data-testid="audit-actor">
      {username === undefined ? (
        <ShortId id={e.actor_id} />
      ) : (
        <span className={cn("font-semibold", TABLE_NOWRAP)} title={e.actor_id} data-id={e.actor_id} data-username={username}>
          {username}
        </span>
      )}
      <span className="text-xs text-muted-foreground">{t(`cisp.console.audit.actor_type.${e.actor_type}`)}</span>
    </div>
  );
}

/** The payload as terms and values, and the whole JSON behind a disclosure. */
function Payload({ payload }: { payload: Record<string, unknown> }) {
  const t = useT();
  const entries = Object.entries(payload);
  return (
    <div className="flex min-w-0 flex-col gap-2" data-testid="audit-payload">
      {entries.length === 0 ? (
        <p className="m-0 text-xs text-muted-foreground">{t("cisp.console.audit.payload_empty")}</p>
      ) : (
        <Facts
          items={entries.map(([k, v]) => {
            const label = payloadKeyLabel(t, k);
            return {
              id: k,
              term: label ?? k,
              value: <span data-member={k}>{payloadValue(t, k, v)}</span>,
            };
          })}
        />
      )}
      <details className="text-xs">
        <summary className="w-fit cursor-pointer text-muted-foreground hover:text-foreground">{t("cisp.console.audit.full_json")}</summary>
        <pre
          className="m-0 mt-1 max-w-full overflow-x-auto rounded-md border border-border bg-card p-2 font-mono text-xs break-all whitespace-pre-wrap"
          data-testid="audit-json"
        >
          {JSON.stringify(payload, null, 2)}
        </pre>
      </details>
    </div>
  );
}

/** One event: number, time, actor and type in the row; entity, hashes and payload behind its expander. */
function AuditRow({ e, usernames }: { e: AuditEvent; usernames: ReadonlyMap<string, string> }) {
  const t = useT();
  const x = useExpander();
  const label = eventLabel(t, e.event_type);
  return (
    <>
      <TableRow data-event={e.event_type} data-event-id={e.id}>
        <ExpandCell {...x} label={`${t("cisp.console.audit.id")} ${e.id}`} />
        <TableCell className={cn("font-mono text-xs tabular-nums", TABLE_NOWRAP)}>{e.id}</TableCell>
        <TableCell>
          <Time iso={e.ts} />
        </TableCell>
        <TableCell>
          <Actor e={e} usernames={usernames} />
        </TableCell>
        <TableCell>
          {label === null ? (
            <code className="font-mono text-xs" data-testid="audit-event-type" data-code={e.event_type}>
              {e.event_type}
            </code>
          ) : (
            <span title={e.event_type} data-testid="audit-event-type" data-code={e.event_type} className="inline-flex">
              <StatusBadge tone="neutral" variant="outline" dot={false} className="h-auto min-h-6 py-0.5 whitespace-normal">
                {label}
              </StatusBadge>
            </span>
          )}
        </TableCell>
      </TableRow>
      <DetailsRow open={x.open} detailsId={x.detailsId} colSpan={5}>
        <div className="grid gap-3 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
          <Facts
            items={[
              { term: t("cisp.console.audit.event_code"), value: <code className="font-mono">{e.event_type}</code> },
              { term: t("cisp.console.audit.actor_id"), value: <CopyId id={e.actor_id} /> },
              {
                term: t("cisp.console.audit.entity"),
                testId: "audit-entity",
                value: (
                  <span className="inline-flex flex-wrap items-center gap-x-2">
                    <span>{e.entity_type}</span>
                    <CopyId id={e.entity_id} />
                  </span>
                ),
              },
              { term: t("cisp.console.audit.hash"), value: <CopyId id={e.hash} /> },
              ...(e.prev_hash === undefined ? [] : [{ term: t("cisp.console.audit.prev_hash"), value: <CopyId id={e.prev_hash} /> }]),
            ]}
          />
          <Payload payload={e.payload} />
        </div>
      </DetailsRow>
    </>
  );
}

export interface AuditFilter {
  since: string;
  actor: string;
  type: string;
}

/** The query of a filter: empty members left out, since as RFC 3339 UTC; null when since cannot be read. */
export function auditQuery(f: AuditFilter, toUtc: (local: string) => string | null): { since?: string; actor?: string; type?: string } | null {
  const q: { since?: string; actor?: string; type?: string } = {};
  if (f.since.trim() !== "") {
    const utc = toUtc(f.since.trim());
    if (utc === null) return null;
    q.since = utc;
  }
  if (f.actor.trim() !== "") q.actor = f.actor.trim();
  if (f.type.trim() !== "") q.type = f.type.trim();
  return q;
}

export function AuditPage() {
  const t = useT();
  const [draft, setDraft] = useState<AuditFilter>({ since: "", actor: "", type: "" });
  const [applied, setApplied] = useState<AuditFilter>(draft);
  const [pages, setPages] = useState<number[]>([]);
  const before = pages.at(-1);
  const query = auditQuery(applied, inputToUtc);
  const list = useLoad(
    async (c) =>
      query === null
        ? null
        : ((await c.GET("/v1/console/audit", { params: { query: { ...query, ...(before === undefined ? {} : { before_id: before }) } } })).data ??
          null),
    `${JSON.stringify(applied)}:${before ?? ""}`,
  );
  // The audit names an account by its id; the accounts list (admin, as
  // this page is) has its username. Without that list, the id is shown.
  const accounts = useLoad(async (c) => (await c.GET("/v1/console/accounts")).data ?? null, "audit-accounts");
  const usernames = new Map((accounts.data?.accounts ?? []).map((a) => [a.id, a.username]));
  return (
    <>
      <ConsoleHeader title={t("cisp.console.nav.audit")} description={t("cisp.console.page.audit")} />
      <form
        className="flex flex-wrap items-end gap-3 rounded-panel border border-border bg-card p-4 shadow-panel"
        onSubmit={(e) => {
          e.preventDefault();
          setPages([]);
          setApplied(draft);
        }}
      >
        <div className="flex flex-col gap-1">
          <Label htmlFor="audit-since">{t("cisp.console.audit.since")}</Label>
          <Input id="audit-since" type="datetime-local" step={1} value={draft.since} onChange={(e) => setDraft({ ...draft, since: e.target.value })} />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor="audit-actor">{t("cisp.console.audit.actor")}</Label>
          <Input id="audit-actor" maxLength={128} value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} />
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor="audit-type">{t("cisp.console.audit.type")}</Label>
          <Input id="audit-type" maxLength={64} value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })} />
        </div>
        <Button type="submit">{t("cisp.console.audit.apply")}</Button>
      </form>
      {query === null && (
        <p role="alert" className="m-0 text-sm text-[var(--us-danger)]">
          {t("cisp.console.audit.since_invalid")}
        </p>
      )}
      {list.failure !== null && <ProblemNotice failure={list.failure} />}
      {list.loading && list.data === null && <Loading />}
      {list.data !== null &&
        (list.data.events.length === 0 ? (
          <p className="m-0 text-sm">{t("cisp.console.audit.none")}</p>
        ) : (
          <TablePanel label={t("cisp.console.nav.audit")}>
            <Table data-testid="audit-table">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <span className="sr-only">{t("cisp.console.row.details")}</span>
                  </TableHead>
                  <TableHead>{t("cisp.console.audit.id")}</TableHead>
                  <TableHead>{t("cisp.console.audit.time")}</TableHead>
                  <TableHead>{t("cisp.console.audit.actor")}</TableHead>
                  <TableHead>{t("cisp.console.audit.type")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.data.events.map((e) => (
                  <AuditRow key={e.id} e={e} usernames={usernames} />
                ))}
              </TableBody>
            </Table>
          </TablePanel>
        ))}
      <div className="flex gap-2">
        {pages.length > 0 && (
          <Button type="button" variant="outline" size="sm" onClick={() => setPages([])}>
            {t("cisp.console.paging.newest")}
          </Button>
        )}
        {list.data?.next_before_id !== undefined && (
          <Button type="button" variant="outline" size="sm" onClick={() => setPages((p) => [...p, list.data?.next_before_id ?? 0])}>
            {t("cisp.console.paging.older")}
          </Button>
        )}
      </div>
    </>
  );
}
