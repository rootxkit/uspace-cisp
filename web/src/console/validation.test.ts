// A refused form is worded in the viewer's language (live use: the ka
// sign-in page showed the API's "code: six digits"). Each refusal has its
// twin: the field the catalogue knows, the one it does not, a 400 without
// a field, and a refusal that is no form problem at all.
import { describe, expect, it } from "vitest";
import { createTranslator } from "@rootxkit/uspace-ui/i18n";
import type { Problem } from "@rootxkit/uspace-ui/model";
import en from "../i18n/en.json";
import { catalogues } from "../i18n/catalogues";
import { localisingFetch } from "./LoginPage";
import { FIELD_SLUGS, VALIDATION_FIELDS, fieldMessages } from "./validation";

const ka = createTranslator("ka", catalogues);
const enT = createTranslator("en", catalogues);

function problem(status: number, slug: string, errors: { field: string; reason: string }[]): Problem {
  return { type: `https://schemas.uspace.ge/problems/${slug}`, title: "Bad request", status, detail: "code: six digits", instance: null, errors };
}

function apiAnswer(status: number, slug: string, errors: { field: string; reason: string }[]): Response {
  return new Response(JSON.stringify({ ...problem(status, slug, errors), instance: undefined }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
}

describe("the sign-in's validation message", () => {
  it("a code the API refuses as not six digits reads in Georgian on the ka page", async () => {
    const f = localisingFetch(ka, () => Promise.resolve(apiAnswer(400, "bad_request", [{ field: "code", reason: "six digits" }])));
    const res = await f("/_bff/login");
    expect(res.status).toBe(400);
    const detail = ((await res.json()) as { detail: string }).detail;
    expect(detail).toBe(ka("cisp.console.validation.field.code"));
    expect(detail).not.toMatch(/six digits/);
    expect(detail).toMatch(/[ა-ჿ]/);
  });

  it("the same refusal reads in English on the en page", async () => {
    const f = localisingFetch(enT, () => Promise.resolve(apiAnswer(400, "bad_request", [{ field: "code", reason: "six digits" }])));
    expect(((await (await f("/_bff/login")).json()) as { detail: string }).detail).toBe("The code is six digits.");
  });

  it("a refusal that names no field and no known slug is worded by its status, never the API's text", async () => {
    const f = localisingFetch(ka, () => Promise.resolve(apiAnswer(502, "upstream_invalid", [])));
    const detail = ((await (await f("/_bff/login")).json()) as { detail: string }).detail;
    expect(detail).toBe(ka("cisp.console.problem.refused", { status: 502 }));
    expect(detail).not.toMatch(/six digits/);
  });
});

describe("fieldMessages", () => {
  it("words a known field from the catalogue and keeps its name", () => {
    expect(fieldMessages(ka, 400, "bad_request", problem(400, "bad_request", [{ field: "reason", reason: "required, 1 to 500 characters" }]))).toEqual([
      { field: "reason", text: ka("cisp.console.validation.field.reason") },
    ]);
  });

  it("words a field the catalogue does not know generically, never with the API's reason", () => {
    const out = fieldMessages(ka, 400, "bad_request", problem(400, "bad_request", [{ field: "zz_new", reason: "must be green" }]));
    expect(out).toEqual([{ field: "zz_new", text: ka("cisp.console.validation.other") }]);
  });

  it("a 400 that names no field is one malformed line", () => {
    expect(fieldMessages(ka, 400, "bad_request", problem(400, "bad_request", []))).toEqual([{ field: "", text: ka("cisp.console.validation.refused") }]);
  });

  it("a 409 naming its field is worded by its slug", () => {
    const out = fieldMessages(ka, 409, "username_taken", problem(409, "username_taken", [{ field: "username", reason: "another account has this username" }]));
    expect(out).toEqual([{ field: "username", text: ka("cisp.console.validation.slug.username_taken") }]);
  });

  it("a refusal that is no form problem (no field, not 400) is null: the notice keeps its own lead", () => {
    expect(fieldMessages(ka, 503, "database_unavailable", problem(503, "database_unavailable", []))).toBeNull();
    expect(fieldMessages(ka, 503, null, null)).toBeNull();
  });

  it("every field and slug it words has an en key (the parity test covers ka)", () => {
    const keys = Object.keys(en);
    for (const f of VALIDATION_FIELDS) expect(keys).toContain(`cisp.console.validation.field.${f}`);
    for (const s of FIELD_SLUGS) expect(keys).toContain(`cisp.console.validation.slug.${s}`);
  });
});
