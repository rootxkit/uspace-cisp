"use client";

// The signed-in console: who the caller is (GET /v1/console/me) and the
// client every page calls through. A 401 from any call sends the browser
// to the sign-in page; the role shown here only arranges the page, the
// API decides every request.
import { createContext, useCallback, useContext, useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useLang } from "@rootxkit/uspace-ui/i18n";
import type { components } from "../api/types";
import { consoleClient, failureOf, type CallFailure, type ConsoleClient } from "./client";
import { isRole, type ConsoleRole } from "./roles";

export type ConsoleMe = components["schemas"]["ConsoleMe"];

export interface ConsoleContextValue {
  client: ConsoleClient;
  me: ConsoleMe | null;
  role: ConsoleRole | null;
  /** /me could not be read for a reason other than a 401. */
  meFailure: CallFailure | null;
}

const Ctx = createContext<ConsoleContextValue | null>(null);

export function useConsole(): ConsoleContextValue {
  const v = useContext(Ctx);
  if (v === null) throw new Error("useConsole outside ConsoleProvider");
  return v;
}

export function loginPath(lang: string): string {
  return `/${lang}/console/login`;
}

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const { lang } = useLang();
  const router = useRouter();
  const toLogin = useCallback(() => router.replace(loginPath(lang)), [router, lang]);
  const client = useMemo(() => consoleClient(() => lang, toLogin), [lang, toLogin]);
  const [me, setMe] = useState<ConsoleMe | null>(null);
  const [meFailure, setMeFailure] = useState<CallFailure | null>(null);

  useEffect(() => {
    let live = true;
    client
      .GET("/v1/console/me")
      .then(({ data }) => {
        if (!live || data === undefined) return;
        setMe(data);
        setMeFailure(null);
      })
      .catch((err: unknown) => {
        if (!live) return;
        const f = failureOf(err);
        // A 401 is the client's onUnauthorized: the sign-in page.
        if (f.status !== 401) setMeFailure(f);
      });
    return () => {
      live = false;
    };
  }, [client]);

  const role = me !== null && isRole(me.account.role) ? me.account.role : null;
  const value = useMemo(() => ({ client, me, role, meFailure }), [client, me, role, meFailure]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export interface Loaded<T> {
  data: T | null;
  failure: CallFailure | null;
  loading: boolean;
  reload(): void;
}

/**
 * One read of the console API: `load` runs on mount, when `key` changes
 * and on `reload()`. An answer that arrives after a newer request is
 * dropped. A failure keeps the last data and is shown beside it.
 */
export function useLoad<T>(load: (c: ConsoleClient) => Promise<T>, key: string): Loaded<T> {
  const { client } = useConsole();
  const [tick, setTick] = useState(0);
  const [settled, setSettled] = useState<{ request: string; data: T | null; failure: CallFailure | null }>({
    request: "",
    data: null,
    failure: null,
  });
  const seq = useRef(0);
  const request = `${key}#${tick}`;
  const run = useEffectEvent((c: ConsoleClient) => load(c));

  useEffect(() => {
    const mine = ++seq.current;
    run(client)
      .then((d) => {
        if (mine === seq.current) setSettled({ request, data: d, failure: null });
      })
      .catch((err: unknown) => {
        if (mine === seq.current) setSettled((prev) => ({ request, data: prev.data, failure: failureOf(err) }));
      });
  }, [client, request]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data: settled.data, failure: settled.failure, loading: settled.request !== request, reload };
}
