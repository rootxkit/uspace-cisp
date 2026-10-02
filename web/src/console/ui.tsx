"use client";

// The console's small display parts: a time in the viewer's zone with
// its UTC value on hover, a state badge, the API's refusal shown in
// full, and the confirm-with-a-reason action every audited act goes
// through.
import { useState, useSyncExternalStore, type ReactNode } from "react";
import { fmtTimeUTC, LOCALES, useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { Button } from "@rootxkit/uspace-ui/ui";
import { TONE_CLASS, type BadgeSpec } from "./badges";
import { failureOf, type CallFailure } from "./client";

function noSubscribe(): () => void {
  return () => undefined;
}

/** True in the browser after hydration; false while rendering on the server. */
export function useInBrowser(): boolean {
  return useSyncExternalStore(
    noSubscribe,
    () => true,
    () => false,
  );
}

/**
 * The viewer's local rendering of an RFC 3339 instant ("2 Oct 2026,
 * 18:03:00 GMT+4"); the UTC value is the title. The server, which does not
 * know the viewer's zone, renders the UTC value (spec 03 preamble: convert
 * at the display layer only).
 */
export function localTime(iso: string, lang: "ka" | "en"): string | null {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return new Intl.DateTimeFormat(LOCALES[lang], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    timeZoneName: "short",
  }).format(new Date(ms));
}

export function Time({ iso }: { iso: string | null | undefined }) {
  const { lang } = useLang();
  const browser = useInBrowser();
  if (iso === null || iso === undefined || iso === "") return <span>—</span>;
  const utc = fmtTimeUTC(iso, lang, { seconds: true });
  const local = browser ? localTime(iso, lang) : null;
  return (
    <time dateTime={iso} title={utc} className="whitespace-nowrap">
      {local ?? utc}
    </time>
  );
}

/** A state as a badge, labelled from the catalogue, or as sent when unknown. */
export function StateBadge({ spec, value }: { spec: BadgeSpec; value: string }) {
  const t = useT();
  return (
    <span
      data-state={value}
      data-tone={spec.tone}
      className={`inline-block rounded border px-1.5 py-0.5 text-xs ${TONE_CLASS[spec.tone]}`}
    >
      {spec.labelKey === null ? value : t(spec.labelKey)}
    </span>
  );
}

/**
 * A refused or failed call, visibly: the status, what it means for the
 * operator (a 403 names the role), and the API's title and detail with
 * its field problems. Never a silent empty table.
 */
export function ProblemNotice({ failure }: { failure: CallFailure }) {
  const t = useT();
  const p = failure.problem;
  const lead =
    failure.status === 0
      ? t("cisp.console.problem.unreachable")
      : failure.status === 403
        ? t("cisp.console.problem.forbidden")
        : failure.status === 404
          ? t("cisp.console.problem.not_found")
          : t("cisp.console.problem.refused", { status: failure.status });
  return (
    <div role="alert" data-status={failure.status} className="rounded border border-[var(--us-danger)] p-3 text-sm">
      <p className="m-0 font-semibold text-[var(--us-danger)]">{lead}</p>
      {p !== null && (
        <p className="m-0 mt-1">
          <span>{p.title}</span>
          {p.detail !== null && p.detail !== "" && <span>: {p.detail}</span>}
          <span className="ms-2 text-xs text-[var(--us-text-muted)]">({failure.status})</span>
        </p>
      )}
      {p !== null && p.errors.length > 0 && (
        <ul className="m-0 mt-1 ps-5">
          {p.errors.map((e, i) => (
            <li key={`${e.field}-${i}`}>
              <code>{e.field}</code>: {e.reason}
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
    <div className="flex flex-col items-start gap-1">
      <ConfirmDialog
        titleKey={props.titleKey}
        bodyKey={props.bodyKey}
        {...(props.vars === undefined ? {} : { vars: props.vars })}
        reason={{ required: true, minLength: 1 }}
        destructive={props.destructive ?? false}
        onConfirm={(reason) => void run(reason ?? "")}
        trigger={
          <Button type="button" size="sm" variant="outline" disabled={busy} data-testid={props.testId}>
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

/** A section with a heading. */
export function Section({ titleKey, vars, children }: { titleKey: string; vars?: Record<string, string | number>; children: ReactNode }) {
  const t = useT();
  return (
    <section className="flex flex-col gap-2">
      <h3 className="m-0 text-base font-semibold">{t(titleKey, vars)}</h3>
      {children}
    </section>
  );
}

/** "Loading" while the first answer is out. */
export function Loading() {
  const t = useT();
  return (
    <p role="status" className="m-0 text-sm text-[var(--us-text-muted)]">
      {t("cisp.console.loading")}
    </p>
  );
}
