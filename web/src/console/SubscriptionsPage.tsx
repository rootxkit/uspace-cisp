"use client";

// Subscriptions: every client's subscriptions (GET
// /v1/console/subscriptions) with status, datasets, box, last success,
// consecutive failures and deliveries per state; and a subscription's
// page with its deliveries and their attempt log (GET
// /v1/console/subscriptions/{id}/deliveries) and the publisher_admin
// actions suspend, resume and retry, each confirmed with its consequence
// and a reason.
import { useState } from "react";
import Link from "next/link";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { DELIVERY_STATES, deliveryBadge, SUBSCRIPTION_STATUSES, subscriptionBadge } from "./badges";
import { BBoxPreview, fmtBBox } from "./BBoxPreview";
import type { ConsoleClient } from "./client";
import { useConsole, useLoad } from "./context";
import { reasonLabel } from "./PublicationsPage";
import { mayAct } from "./roles";
import { Loading, ProblemNotice, ReasonAction, Section, StateBadge, Time } from "./ui";

type ConsoleSubscription = components["schemas"]["ConsoleSubscription"];
type SubscriptionStatus = components["schemas"]["Subscription"]["status"];
type Delivery = components["schemas"]["Delivery"];

/** The pages of the list read to find one subscription, at most. A bound, not a policy. */
export const FIND_MAX_PAGES = 20;
const FIND_PAGE_ROWS = 500;

/** The deliveries a retry is offered for: not in flight, not delivered. */
export function retryable(state: string): boolean {
  return state === "failed" || state === "expired" || state === "queued";
}

function Counts({ s }: { s: ConsoleSubscription }) {
  const t = useT();
  return (
    <span className="text-xs">
      {DELIVERY_STATES.map((st) => `${t(`cisp.console.delivery.state.${st}`)} ${s.deliveries[st]}`).join(" · ")}
    </span>
  );
}

export function SubscriptionsPage() {
  const t = useT();
  const { lang } = useLang();
  const [status, setStatus] = useState<SubscriptionStatus | "">("");
  const [after, setAfter] = useState<string[]>([]);
  const cursor = after.at(-1);
  const list = useLoad(
    async (c) =>
      (
        await c.GET("/v1/console/subscriptions", {
          params: { query: { ...(status === "" ? {} : { status }), ...(cursor === undefined ? {} : { after: cursor }) } },
        })
      ).data ?? null,
    `${status}:${cursor ?? ""}`,
  );
  return (
    <div className="flex flex-col gap-3">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.subscriptions")}</h2>
      <label className="flex items-center gap-2 text-sm">
        {t("cisp.console.subscriptions.filter")}
        <select
          className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
          value={status}
          onChange={(e) => {
            setAfter([]);
            setStatus(e.target.value as SubscriptionStatus | "");
          }}
        >
          <option value="">{t("cisp.console.filter.all")}</option>
          {SUBSCRIPTION_STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`cisp.console.subscription.status.${s}`)}
            </option>
          ))}
        </select>
      </label>
      {list.failure !== null && <ProblemNotice failure={list.failure} />}
      {list.loading && list.data === null && <Loading />}
      {list.data !== null &&
        (list.data.subscriptions.length === 0 ? (
          <p className="m-0 text-sm">{t("cisp.console.subscriptions.none")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("cisp.console.subscriptions.subscription")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.status")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.datasets")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.bbox")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.last_success")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.failures")}</TableHead>
                <TableHead>{t("cisp.console.subscriptions.deliveries")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.data.subscriptions.map((cs) => {
                const s = cs.subscription;
                return (
                  <TableRow key={s.id} data-subscription={s.id}>
                    <TableCell>
                      <Link href={`/${lang}/console/subscriptions/${encodeURIComponent(s.id)}`} className="font-mono underline">
                        {s.id}
                      </Link>
                      <div className="text-xs">{s.client_id}</div>
                    </TableCell>
                    <TableCell>
                      <StateBadge spec={subscriptionBadge(s.status)} value={s.status} />
                    </TableCell>
                    <TableCell>{s.datasets.map((d) => t(`cisp.console.dataset.${d}`)).join(", ")}</TableCell>
                    <TableCell className="font-mono text-xs">{fmtBBox(s.bbox) ?? t("cisp.console.subscriptions.bbox_none")}</TableCell>
                    <TableCell>
                      <Time iso={s.last_success_at} />
                    </TableCell>
                    <TableCell className={s.consecutive_failures > 0 ? "font-semibold text-[var(--us-danger)]" : ""}>
                      {s.consecutive_failures}
                    </TableCell>
                    <TableCell>
                      <Counts s={cs} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        ))}
      <div className="flex gap-2">
        {after.length > 0 && (
          <Button type="button" variant="outline" size="sm" onClick={() => setAfter([])}>
            {t("cisp.console.paging.first")}
          </Button>
        )}
        {list.data?.next_after !== undefined && (
          <Button type="button" variant="outline" size="sm" onClick={() => setAfter((a) => [...a, list.data?.next_after ?? ""])}>
            {t("cisp.console.paging.next")}
          </Button>
        )}
      </div>
    </div>
  );
}

/** One subscription from the list, read page by page up to FIND_MAX_PAGES. */
async function findSubscription(c: ConsoleClient, id: string): Promise<ConsoleSubscription | null> {
  let after: string | undefined;
  for (let page = 0; page < FIND_MAX_PAGES; page++) {
    const { data } = await c.GET("/v1/console/subscriptions", {
      params: { query: { limit: FIND_PAGE_ROWS, ...(after === undefined ? {} : { after }) } },
    });
    const hit = data?.subscriptions.find((s) => s.subscription.id === id);
    if (hit !== undefined) return hit;
    if (data?.next_after === undefined) return null;
    after = data.next_after;
  }
  return null;
}

function AttemptLog({ d }: { d: Delivery }) {
  const t = useT();
  if (d.log === undefined || d.log.length === 0) return <p className="m-0 text-xs">{t("cisp.console.deliveries.no_attempts")}</p>;
  return (
    <ol className="m-0 ps-5 text-xs" data-testid="attempt-log">
      {d.log.map((a) => (
        <li key={`${a.attempt}-${a.at}`}>
          <Time iso={a.at} />{" "}
          {t("cisp.console.deliveries.attempt", {
            attempt: a.attempt,
            code: a.status_code ?? "—",
            latency: a.latency_ms,
            instance: a.deliver_instance,
          })}
          {a.error !== undefined && a.error !== "" && <span className="ms-1 text-[var(--us-danger)]">{a.error}</span>}
        </li>
      ))}
    </ol>
  );
}

export function SubscriptionPage({ id }: { id: string }) {
  const t = useT();
  const { lang } = useLang();
  const { client, role } = useConsole();
  const sub = useLoad((c) => findSubscription(c, id), id);
  const deliveries = useLoad(
    async (c) => (await c.GET("/v1/console/subscriptions/{id}/deliveries", { params: { path: { id } } })).data ?? null,
    id,
  );
  const reloadAll = () => {
    sub.reload();
    deliveries.reload();
  };
  const s = sub.data?.subscription;
  return (
    <div className="flex flex-col gap-4">
      <Link href={`/${lang}/console/subscriptions`} className="text-sm underline">
        {t("cisp.console.subscriptions.back")}
      </Link>
      <h2 className="m-0 font-mono text-lg font-bold">{id}</h2>
      {sub.failure !== null && <ProblemNotice failure={sub.failure} />}
      {sub.loading && sub.data === null && <Loading />}
      {!sub.loading && sub.data === null && sub.failure === null && (
        <p role="alert" className="m-0 text-sm">
          {t("cisp.console.subscriptions.not_found", { pages: FIND_MAX_PAGES })}
        </p>
      )}
      {s !== undefined && (
        <>
          <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt>{t("cisp.console.subscriptions.client")}</dt>
            <dd className="m-0">{s.client_id}</dd>
            <dt>{t("cisp.console.subscriptions.status")}</dt>
            <dd className="m-0" data-testid="subscription-status">
              <StateBadge spec={subscriptionBadge(s.status)} value={s.status} />
              {s.suspended_reason !== undefined && <span className="ms-2 text-xs">{s.suspended_reason}</span>}
            </dd>
            <dt>{t("cisp.console.subscriptions.callback")}</dt>
            <dd className="m-0 break-all font-mono text-xs">{s.callback_url}</dd>
            <dt>{t("cisp.console.subscriptions.datasets")}</dt>
            <dd className="m-0">{s.datasets.map((d) => t(`cisp.console.dataset.${d}`)).join(", ")}</dd>
            <dt>{t("cisp.console.subscriptions.last_success")}</dt>
            <dd className="m-0">
              <Time iso={s.last_success_at} />
            </dd>
            <dt>{t("cisp.console.subscriptions.failures")}</dt>
            <dd className="m-0">
              {s.consecutive_failures}
              {s.failing_since !== undefined && (
                <>
                  {" "}
                  {t("cisp.console.subscriptions.failing_since")} <Time iso={s.failing_since} />
                </>
              )}
            </dd>
          </dl>
          <div className="flex flex-wrap gap-3">
            {mayAct(role, "suspend") && (s.status === "active" || s.status === "pending_verification") && (
              <ReasonAction
                testId="suspend"
                labelKey="cisp.console.subscriptions.suspend"
                titleKey="cisp.console.subscriptions.suspend_title"
                bodyKey="cisp.console.subscriptions.suspend_body"
                doneKey="cisp.console.subscriptions.suspended"
                vars={{ id: s.id, client: s.client_id }}
                destructive
                act={(reason) => client.POST("/v1/console/subscriptions/{id}/suspend", { params: { path: { id: s.id } }, body: { reason } })}
                onDone={reloadAll}
              />
            )}
            {mayAct(role, "resume") && s.status === "suspended" && (
              <ReasonAction
                testId="resume"
                labelKey="cisp.console.subscriptions.resume"
                titleKey="cisp.console.subscriptions.resume_title"
                bodyKey="cisp.console.subscriptions.resume_body"
                doneKey="cisp.console.subscriptions.resumed"
                vars={{ id: s.id, client: s.client_id }}
                act={(reason) => client.POST("/v1/console/subscriptions/{id}/resume", { params: { path: { id: s.id } }, body: { reason } })}
                onDone={reloadAll}
              />
            )}
          </div>
          <Section titleKey="cisp.console.subscriptions.bbox">
            <BBoxPreview bbox={s.bbox} />
          </Section>
        </>
      )}
      <Section titleKey="cisp.console.deliveries.title">
        {deliveries.failure !== null && <ProblemNotice failure={deliveries.failure} />}
        {deliveries.data !== null && deliveries.data.log !== "complete" && (
          <p role="alert" className="m-0 text-sm font-semibold" data-testid="log-state">
            {t(`cisp.console.deliveries.log.${deliveries.data.log}`)}
          </p>
        )}
        {deliveries.data !== null &&
          (deliveries.data.deliveries.length === 0 ? (
            <p className="m-0 text-sm">{t("cisp.console.deliveries.none")}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("cisp.console.deliveries.delivery")}</TableHead>
                  <TableHead>{t("cisp.console.deliveries.state")}</TableHead>
                  <TableHead>{t("cisp.console.deliveries.attempts")}</TableHead>
                  <TableHead>{t("cisp.console.deliveries.last_code")}</TableHead>
                  <TableHead>{t("cisp.console.deliveries.next_retry")}</TableHead>
                  <TableHead>{t("cisp.console.deliveries.log_title")}</TableHead>
                  <TableHead>{t("cisp.console.publications.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {deliveries.data.deliveries.map((d) => (
                  <TableRow key={d.id} data-delivery={d.id}>
                    <TableCell>
                      <div className="font-mono text-xs">{d.id}</div>
                      <div className="text-xs">
                        {reasonLabel(t, d.reason)}
                        {d.change_id !== undefined && ` · ${t("cisp.console.deliveries.change", { change: d.change_id })}`}
                      </div>
                    </TableCell>
                    <TableCell data-testid="delivery-state">
                      <StateBadge spec={deliveryBadge(d.state)} value={d.state} />
                    </TableCell>
                    <TableCell>{d.attempts}</TableCell>
                    <TableCell className="max-w-[16rem] whitespace-normal break-words">
                      {d.last_status_code ?? "—"}
                      {d.last_error !== undefined && d.last_error !== "" && <div className="text-xs">{d.last_error}</div>}
                    </TableCell>
                    <TableCell>
                      <Time iso={d.next_retry_at} />
                    </TableCell>
                    <TableCell className="min-w-[24rem] whitespace-normal break-words">
                      <AttemptLog d={d} />
                    </TableCell>
                    <TableCell>
                      {mayAct(role, "retry") && retryable(d.state) && (
                        <ReasonAction
                          testId={`retry-${d.id}`}
                          labelKey="cisp.console.deliveries.retry"
                          titleKey="cisp.console.deliveries.retry_title"
                          bodyKey="cisp.console.deliveries.retry_body"
                          doneKey="cisp.console.deliveries.retried"
                          vars={{ delivery: d.id, client: s?.client_id ?? "" }}
                          act={(reason) =>
                            client.POST("/v1/console/subscriptions/{id}/deliveries/{delivery_id}/retry", {
                              params: { path: { id, delivery_id: d.id } },
                              body: { reason },
                            })
                          }
                          onDone={reloadAll}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ))}
      </Section>
    </div>
  );
}
