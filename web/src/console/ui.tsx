"use client";

// The console's small display parts: a time in UTC laid out for the
// page's language, a state badge, the API's refusal shown in full, and
// the confirm-with-a-reason action every audited act goes through.
import { useState, type ReactNode } from "react";
import { useT, type Translate } from "@rootxkit/uspace-ui/i18n";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { Button, Panel, StatusBadge } from "@rootxkit/uspace-ui/ui";
import { TONE_STATUS, type BadgeSpec } from "./badges";
import { failureOf, type CallFailure } from "./client";
import { fieldMessages } from "./validation";

function two(n: number): string {
  return String(n).padStart(2, "0");
}

/**
 * An RFC 3339 instant in UTC, laid out for the page's language from the
 * catalogue ("15 Oct 2026, 22:07:49 UTC", "15 ოქტ. 2026, 22:07:49 UTC"):
 * the console says UTC everywhere, as its filters do, never the viewer's
 * zone. The month names are the catalogue's, not the browser's: a browser
 * without Georgian locale data formats ka-GE in English. Null when the
 * value is not a time.
 */
export function utcTime(iso: string, t: Translate): string | null {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return t("cisp.console.time.utc", {
    day: d.getUTCDate(),
    month: t(`cisp.console.time.month.${d.getUTCMonth() + 1}`),
    year: d.getUTCFullYear(),
    time: `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}`,
  });
}

/** utcTime in the page's language, with a dash for a value that is not a time. */
export function useUtcTime(): (iso: string) => string {
  const t = useT();
  return (iso) => utcTime(iso, t) ?? "—";
}

/** A time in UTC in the page's language; its RFC 3339 value is the title. */
export function Time({ iso }: { iso: string | null | undefined }) {
  const t = useT();
  if (iso === null || iso === undefined || iso === "") return <span>—</span>;
  return (
    <time dateTime={iso} title={iso} className="whitespace-nowrap" data-testid="utc-time">
      {utcTime(iso, t) ?? iso}
    </time>
  );
}

/** A state as a badge, labelled from the catalogue, or as sent when unknown; `wrap` lets a long label wrap in a narrow column. */
export function StateBadge({ spec, value, wrap = false }: { spec: BadgeSpec; value: string; wrap?: boolean }) {
  const t = useT();
  return (
    <StatusBadge
      {...(wrap ? { className: "h-auto min-h-6 py-0.5 whitespace-normal" } : {})}
      data-state={value}
      data-tone={spec.tone}
      tone={TONE_STATUS[spec.tone]}
      variant={spec.tone === "unknown" ? "outline" : "soft"}
    >
      {spec.labelKey === null ? value : t(spec.labelKey)}
    </StatusBadge>
  );
}

/**
 * A refused or failed call, visibly: the status, what it means for the
 * operator (a 403 names the role), each refused field worded in the
 * viewer's language, or else the API's title and detail. Never a silent
 * empty table.
 */
export function ProblemNotice({ failure }: { failure: CallFailure }) {
  const t = useT();
  const p = failure.problem;
  // A refused form (a 400, or a problem naming its fields) is worded by
  // the catalogue; the API's own title, detail and reasons are English
  // and are not shown in its place (src/console/validation.ts).
  const fields = failure.status === 0 ? null : fieldMessages(t, failure.status, failure.slug, p);
  const lead =
    failure.status === 0
      ? t("cisp.console.problem.unreachable")
      : failure.status === 403
        ? t("cisp.console.problem.forbidden")
        : failure.status === 404
          ? t("cisp.console.problem.not_found")
          : t("cisp.console.problem.refused", { status: failure.status });
  return (
    <div
      role="alert"
      data-status={failure.status}
      className="rounded-panel border border-[var(--us-danger)] bg-card p-3 text-sm text-card-foreground shadow-panel"
    >
      <p className="m-0 font-semibold text-[var(--us-danger)]">{lead}</p>
      {p !== null && fields === null && (
        <p className="m-0 mt-1">
          <span>{p.title}</span>
          {p.detail !== null && p.detail !== "" && <span>: {p.detail}</span>}
          <span className="ms-2 text-xs text-[var(--us-text-muted)]">({failure.status})</span>
        </p>
      )}
      {fields !== null && (
        <ul className="m-0 mt-1 ps-5" data-testid="field-problems">
          {fields.map((m, i) => (
            <li key={`${m.field}-${i}`} data-field={m.field}>
              {m.text}
              {m.field !== "" && <code className="ms-2 text-xs text-[var(--us-text-muted)]">{m.field}</code>}
            </li>
          ))}
        </ul>
      )}
      {failure.retryAfterS !== null && failure.retryAfterS > 0 && (
        <p className="m-0 mt-1">{t("cisp.console.problem.retry_after", { seconds: failure.retryAfterS })}</p>
      )}
    </div>
  );
}

/** The largest reason the API takes (ConsoleActionReason.reason maxLength). */
export const REASON_MAX_CHARS = 500;

/**
 * An audited act: a button that opens the kit's ConfirmDialog with the
 * consequence spelled out and a required reason, then `act(reason)`. The
 * API's answer is shown under the button: its refusal in full (a 403
 * included), or `doneKey` once it is done.
 */
export function ReasonAction(props: {
  labelKey: string;
  titleKey: string;
  bodyKey: string;
  vars?: Record<string, string | number>;
  destructive?: boolean;
  doneKey: string;
  act(reason: string): Promise<unknown>;
  onDone?(): void;
  testId?: string;
}) {
  const t = useT();
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const run = async (reason: string) => {
    setFailure(null);
    setDone(false);
    if (reason.length > REASON_MAX_CHARS) {
      setFailure({
        status: 400,
        problem: {
          type: "",
          title: t("cisp.console.action.reason_too_long", { max: REASON_MAX_CHARS }),
          status: 400,
          detail: null,
          instance: null,
          errors: [],
        },
        slug: null,
        retryAfterS: null,
      });
      return;
    }
    setBusy(true);
    try {
      await props.act(reason);
      setDone(true);
      props.onDone?.();
    } catch (err: unknown) {
      setFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex max-w-full min-w-0 flex-col items-start gap-1">
      <ConfirmDialog
        titleKey={props.titleKey}
        bodyKey={props.bodyKey}
        {...(props.vars === undefined ? {} : { vars: props.vars })}
        reason={{ required: true, minLength: 1 }}
        destructive={props.destructive ?? false}
        onConfirm={(reason) => void run(reason ?? "")}
        trigger={
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            data-testid={props.testId}
            className="h-auto min-h-8 max-w-full py-1 text-start whitespace-normal"
          >
            {t(props.labelKey)}
          </Button>
        }
      />
      {done && (
        <p role="status" className="m-0 text-xs">
          {t(props.doneKey, props.vars)}
        </p>
      )}
      {failure !== null && <ProblemNotice failure={failure} />}
    </div>
  );
}

/** A titled panel of a console page (the kit's Panel, named by its heading). */
export function Section({
  titleKey,
  vars,
  description,
  actions,
  flush,
  children,
}: {
  titleKey: string;
  vars?: Record<string, string | number>;
  description?: ReactNode;
  actions?: ReactNode;
  /** A table runs edge to edge. */
  flush?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  return (
    <Panel
      title={t(titleKey, vars)}
      bodyClassName="flex flex-col gap-2"
      padding={flush === true ? "none" : "default"}
      {...(description === undefined ? {} : { description })}
      {...(actions === undefined ? {} : { actions })}
    >
      {children}
    </Panel>
  );
}

/**
 * A table in a panel without a heading of its own (the page's header
 * names it). The panel is the table's horizontal scroller, a labelled
 * region the keyboard can reach and scroll (WCAG 2.1.1), so a wide table
 * stays readable beside the sidebar.
 */
export function TablePanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Panel padding="none">
      <ScrollRegion label={label}>{children}</ScrollRegion>
    </Panel>
  );
}

/** A table's horizontal scroller: a labelled region the keyboard can reach. */
export function ScrollRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      role="region"
      aria-label={label}
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a region that scrolls must be reachable by keyboard (WCAG 2.1.1; axe scrollable-region-focusable)
      tabIndex={0}
      className="overflow-x-auto outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset [&_[data-slot=table-container]]:overflow-visible [&_td:first-child]:ps-4 [&_td:last-child]:pe-4 [&_th:first-child]:ps-4 [&_th:last-child]:pe-4"
    >
      {children}
    </div>
  );
}

/** "Loading" while the first answer is out. */
export function Loading() {
  const t = useT();
  return (
    <p role="status" className="m-0 text-sm text-muted-foreground">
      {t("cisp.console.loading")}
    </p>
  );
}
