"use client";

// Accounts (admin): the list (GET /v1/console/accounts), creating one
// (POST; the one-time initial password and the TOTP enrolment URL shown
// once, with a copy button and a warning), and role, status and MFA
// changes (PATCH), each confirmed with its consequence. The API records
// account changes with the actor and the change and takes no reason
// (docs/PLAN.md §15 Q40 (5)), so these dialogs ask none. Below admin the
// page still asks the API, and shows its 403.
import { useState } from "react";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { Button, Input, Label, Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@rootxkit/uspace-ui/ui";
import type { components } from "../api/types";
import { failureOf, type CallFailure } from "./client";
import { useConsole, useLoad } from "./context";
import { ROLES, type ConsoleRole } from "./roles";
import { Loading, ProblemNotice, Section, Time } from "./ui";

type Account = components["schemas"]["ConsoleAccount"];
type Created = components["schemas"]["ConsoleAccountCreated"];
type Patch = components["schemas"]["ConsoleAccountPatch"];

/** The username rule the API applies (lower case, 3-64 of a-z 0-9 . _ -), to say so before sending. */
export const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;

function CopyValue({ value, testId }: { value: string; testId: string }) {
  const t = useT();
  const [copied, setCopied] = useState<boolean | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <code className="break-all rounded bg-[var(--us-surface-sunken)] px-2 py-1 font-mono" data-testid={testId}>
        {value}
      </code>
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={() => {
          navigator.clipboard
            .writeText(value)
            .then(() => setCopied(true))
            .catch(() => setCopied(false));
        }}
      >
        {t("cisp.console.accounts.copy")}
      </Button>
      {copied === true && <span role="status">{t("cisp.console.accounts.copied")}</span>}
      {copied === false && <span role="alert">{t("cisp.console.accounts.copy_failed")}</span>}
    </div>
  );
}

/** The secrets of a create or an MFA reset, shown once. */
function OnceSecrets({ password, totpUri, onDismiss }: { password?: string; totpUri?: string; onDismiss(): void }) {
  const t = useT();
  return (
    <div role="alert" className="flex flex-col gap-2 rounded border border-[var(--us-danger)] p-3 text-sm" data-testid="once-secrets">
      <p className="m-0 font-semibold">{t("cisp.console.accounts.once_warning")}</p>
      {password !== undefined && (
        <>
          <span>{t("cisp.console.accounts.initial_password")}</span>
          <CopyValue value={password} testId="initial-password" />
        </>
      )}
      {totpUri !== undefined && (
        <>
          <span>{t("cisp.console.accounts.totp_uri")}</span>
          <CopyValue value={totpUri} testId="totp-uri" />
        </>
      )}
      <div>
        <Button type="button" size="sm" onClick={onDismiss}>
          {t("cisp.console.accounts.dismiss")}
        </Button>
      </div>
    </div>
  );
}

function CreateForm({ onCreated }: { onCreated(c: Created): void }) {
  const t = useT();
  const { client } = useConsole();
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<ConsoleRole>("viewer");
  const [mfa, setMfa] = useState(false);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const valid = USERNAME_PATTERN.test(username);
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!valid || busy) return;
        setBusy(true);
        setFailure(null);
        client
          .POST("/v1/console/accounts", { body: { username, role, mfa_required: role === "admin" || mfa } })
          .then(({ data }) => {
            if (data !== undefined) onCreated(data);
            setUsername("");
          })
          .catch((err: unknown) => setFailure(failureOf(err)))
          .finally(() => setBusy(false));
      }}
    >
      <div className="flex flex-col gap-1">
        <Label htmlFor="new-username">{t("cisp.console.accounts.username")}</Label>
        <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} aria-invalid={username !== "" && !valid} />
      </div>
      <div className="flex flex-col gap-1">
        <Label htmlFor="new-role">{t("cisp.console.accounts.role")}</Label>
        <select
          id="new-role"
          className="rounded border border-[var(--us-border)] bg-[var(--us-surface)] px-2 py-1"
          value={role}
          onChange={(e) => setRole(e.target.value as ConsoleRole)}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {t(`cisp.console.role.${r}`)}
            </option>
          ))}
        </select>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={role === "admin" || mfa} disabled={role === "admin"} onChange={(e) => setMfa(e.target.checked)} />
        {t("cisp.console.accounts.mfa_required")}
      </label>
      <Button type="submit" disabled={!valid || busy}>
        {t("cisp.console.accounts.create")}
      </Button>
      {username !== "" && !valid && <p className="m-0 w-full text-xs text-[var(--us-danger)]">{t("cisp.console.accounts.username_rule")}</p>}
      {failure !== null && (
        <div className="w-full">
          <ProblemNotice failure={failure} />
        </div>
      )}
    </form>
  );
}

/** A change to one account, confirmed with what it does. */
function ChangeAction(props: { account: Account; patch: Patch; labelKey: string; bodyKey: string; vars: Record<string, string>; onDone(totpUri?: string): void }) {
  const t = useT();
  const { client } = useConsole();
  const [failure, setFailure] = useState<CallFailure | null>(null);
  return (
    <div className="flex flex-col gap-1">
      <ConfirmDialog
        titleKey={props.labelKey}
        bodyKey={props.bodyKey}
        vars={{ username: props.account.username, ...props.vars }}
        destructive={props.patch.status === "disabled" || props.patch.reset_mfa === true}
        onConfirm={() => {
          setFailure(null);
          client
            .PATCH("/v1/console/accounts/{id}", { params: { path: { id: props.account.id } }, body: props.patch })
            .then(({ data }) => props.onDone(data?.totp_uri))
            .catch((err: unknown) => setFailure(failureOf(err)));
        }}
        trigger={
          <Button type="button" size="sm" variant="outline">
            {t(props.labelKey, { username: props.account.username, ...props.vars })}
          </Button>
        }
      />
      {failure !== null && <ProblemNotice failure={failure} />}
    </div>
  );
}

export function AccountsPage() {
  const t = useT();
  const list = useLoad(async (c) => (await c.GET("/v1/console/accounts")).data ?? null, "accounts");
  const [secrets, setSecrets] = useState<{ password?: string; totpUri?: string } | null>(null);
  return (
    <div className="flex flex-col gap-4">
      <h2 className="m-0 text-lg font-bold">{t("cisp.console.nav.accounts")}</h2>
      {list.failure !== null && <ProblemNotice failure={list.failure} />}
      {secrets !== null && <OnceSecrets {...secrets} onDismiss={() => setSecrets(null)} />}
      {list.failure === null && (
        <Section titleKey="cisp.console.accounts.create_title">
          <CreateForm
            onCreated={(c) => {
              setSecrets({ password: c.initial_password, ...(c.totp_uri === undefined ? {} : { totpUri: c.totp_uri }) });
              list.reload();
            }}
          />
        </Section>
      )}
      {list.loading && list.data === null && <Loading />}
      {list.data !== null && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("cisp.console.accounts.username")}</TableHead>
              <TableHead>{t("cisp.console.accounts.role")}</TableHead>
              <TableHead>{t("cisp.console.accounts.status")}</TableHead>
              <TableHead>{t("cisp.console.accounts.mfa")}</TableHead>
              <TableHead>{t("cisp.console.accounts.last_login")}</TableHead>
              <TableHead>{t("cisp.console.accounts.locked_until")}</TableHead>
              <TableHead>{t("cisp.console.publications.actions")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.accounts.map((a) => (
              <TableRow key={a.id} data-account={a.username}>
                <TableCell className="font-mono">{a.username}</TableCell>
                <TableCell>{t(`cisp.console.role.${a.role}`)}</TableCell>
                <TableCell>{t(`cisp.console.accounts.status.${a.status}`)}</TableCell>
                <TableCell>
                  {t(a.mfa_required ? "cisp.console.accounts.mfa_on" : "cisp.console.accounts.mfa_off")}
                  {a.mfa_required && !a.mfa_enrolled && <span className="ms-1 text-[var(--us-danger)]">{t("cisp.console.accounts.mfa_not_enrolled")}</span>}
                </TableCell>
                <TableCell>
                  <Time iso={a.last_login_at} />
                </TableCell>
                <TableCell>
                  <Time iso={a.locked_until} />
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-2">
                    {ROLES.filter((r) => r !== a.role).map((r) => (
                      <ChangeAction
                        key={r}
                        account={a}
                        patch={{ role: r }}
                        labelKey="cisp.console.accounts.set_role"
                        bodyKey="cisp.console.accounts.set_role_body"
                        vars={{ role: t(`cisp.console.role.${r}`) }}
                        onDone={() => list.reload()}
                      />
                    ))}
                    <ChangeAction
                      account={a}
                      patch={{ status: a.status === "active" ? "disabled" : "active" }}
                      labelKey={a.status === "active" ? "cisp.console.accounts.disable" : "cisp.console.accounts.enable"}
                      bodyKey={a.status === "active" ? "cisp.console.accounts.disable_body" : "cisp.console.accounts.enable_body"}
                      vars={{}}
                      onDone={() => list.reload()}
                    />
                    <ChangeAction
                      account={a}
                      patch={{ reset_mfa: true }}
                      labelKey="cisp.console.accounts.reset_mfa"
                      bodyKey="cisp.console.accounts.reset_mfa_body"
                      vars={{}}
                      onDone={(uri) => {
                        if (uri !== undefined) setSecrets({ totpUri: uri });
                        list.reload();
                      }}
                    />
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
