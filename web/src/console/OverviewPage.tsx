"use client";

// The console's first page: the status document in full (GET
// /v1/console/status): every dataset's current version, every
// publisher's heartbeat and last publication, the degraded components,
// and this API instance's counters since it started.
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import { useLoad } from "./context";
import { ageOnApiClockS } from "./StatusStrip";
import { Loading, ProblemNotice, Section, Time } from "./ui";

export function OverviewPage() {
  const t = useT();
  const st = useLoad(async (c) => (await c.GET("/v1/console/status")).data ?? null, "overview");
  const s = st.data?.status ?? null;
  const counters = Object.entries(st.data?.counters ?? {}).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.overview")}</h2>
      {st.failure !== null && <ProblemNotice failure={st.failure} />}
      {st.loading && st.data === null && <Loading />}
      {s !== null && (
        <>
          <Section titleKey="cisp.console.status.datasets">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("cisp.console.overview.dataset")}</TableHead>
                  <TableHead>{t("cisp.console.publications.version")}</TableHead>
                  <TableHead>{t("cisp.console.overview.updated")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.datasets.map((d) => (
                  <TableRow key={d.dataset}>
                    <TableCell>{t(`cisp.console.dataset.${d.dataset}`)}</TableCell>
                    <TableCell>{d.current_version}</TableCell>
                    <TableCell>
                      <Time iso={d.updated_at} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Section>
          <Section titleKey="cisp.console.status.publishers">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("cisp.console.overview.publisher")}</TableHead>
                  <TableHead>{t("cisp.console.overview.heartbeat")}</TableHead>
                  <TableHead>{t("cisp.console.overview.last_publication")}</TableHead>
                  <TableHead>{t("cisp.console.overview.state")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.publishers.map((p) => {
                  const age = ageOnApiClockS(s.now, p.last_heartbeat_at);
                  return (
                    <TableRow key={p.client_id}>
                      <TableCell className="font-mono">{p.client_id}</TableCell>
                      <TableCell>
                        <Time iso={p.last_heartbeat_at} />
                        {age !== null && <span className="ms-2 text-xs">{t("cisp.console.status.heartbeat_age", { age })}</span>}
                      </TableCell>
                      <TableCell>
                        <Time iso={p.last_publication_at} />
                      </TableCell>
                      <TableCell className={p.stale ? "font-semibold text-[var(--us-danger)]" : ""}>
                        {p.stale ? t("cisp.console.status.stale") : t("cisp.console.overview.fresh")}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Section>
          <Section titleKey="cisp.console.overview.degraded">
            {s.degraded.length === 0 ? (
              <p className="m-0 text-sm">{t("cisp.console.overview.none_degraded")}</p>
            ) : (
              <ul className="m-0 ps-5 text-sm">
                {s.degraded.map((d) => (
                  <li key={d.component} className="font-semibold text-[var(--us-danger)]">
                    {d.component} <Time iso={d.since} /> {d.reason ?? ""}
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section titleKey="cisp.console.overview.counters">
            {counters.length === 0 ? (
              <p className="m-0 text-sm">{t("cisp.console.overview.no_counters")}</p>
            ) : (
              <ul className="m-0 grid grid-cols-1 gap-x-6 ps-0 text-xs sm:grid-cols-2 lg:grid-cols-3">
                {counters.map(([k, v]) => (
                  <li key={k} className="flex list-none justify-between gap-2 font-mono">
                    <span>{k}</span>
                    <span>{v}</span>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}
    </div>
  );
}
