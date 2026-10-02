"use client";

// Audit (admin): the events table (GET /v1/console/audit), newest first,
// filtered by since, actor and type, paged with before_id, each row with
// its actor and payload. The since filter is typed as a UTC wall clock
// (the kit's UTC box, inputToUtc), and its label says so.
import { useState } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { inputToUtc } from "@rootxkit/uspace-ui/form";
import { Button, Input, Label, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { useLoad } from "./context";
import { Loading, ProblemNotice, Time } from "./ui";

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
  return (
    <div className="flex flex-col gap-3">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.audit")}</h2>
      <form
        className="flex flex-wrap items-end gap-3"
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
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("cisp.console.audit.id")}</TableHead>
                <TableHead>{t("cisp.console.audit.time")}</TableHead>
                <TableHead>{t("cisp.console.audit.actor")}</TableHead>
                <TableHead>{t("cisp.console.audit.type")}</TableHead>
                <TableHead>{t("cisp.console.audit.entity")}</TableHead>
                <TableHead>{t("cisp.console.audit.payload")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.data.events.map((e) => (
                <TableRow key={e.id} data-event={e.event_type}>
                  <TableCell className="font-mono text-xs">{e.id}</TableCell>
                  <TableCell>
                    <Time iso={e.ts} />
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-[var(--us-text-muted)]">{t(`cisp.console.audit.actor_type.${e.actor_type}`)}</span>{" "}
                    <span className="font-mono">{e.actor_id}</span>
                  </TableCell>
                  <TableCell className="font-mono">{e.event_type}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {e.entity_type} {e.entity_id}
                  </TableCell>
                  <TableCell>
                    <pre className="m-0 max-w-md overflow-x-auto whitespace-pre-wrap break-all text-xs" data-testid="audit-payload">
                      {JSON.stringify(e.payload, null, 1)}
                    </pre>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
    </div>
  );
}
