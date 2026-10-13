// The console's wording of a refused form: every validation message the
// viewer reads comes from the ka/en catalogues, never the API's English.
// The API names the field it refused (`problem.errors[].field`, its
// `core.FieldError`); the console says what that field takes in the
// viewer's language, and keeps the field's name beside it so a message
// the catalogue does not know is still traceable. The API's own reason
// is never shown in its place (CLAUDE.md rule 9).
import type { Problem } from "@rootxkit/uspace-ui/model";
import type { Translate } from "@rootxkit/uspace-ui/i18n";

/**
 * The fields the console API refuses with 400 on the console's forms,
 * each with a catalogue key `cisp.console.validation.field.<field>`.
 */
export const VALIDATION_FIELDS = [
  "body",
  "code",
  "mfa_token",
  "totp",
  "username",
  "password",
  "role",
  "status",
  "reason",
  "delivery_id",
  "id",
  "dataset",
  "before",
  "before_id",
  "limit",
] as const;

/**
 * The refusals by slug the console words itself for a field problem that
 * is not a 400 (`cisp.console.validation.slug.<slug>`).
 */
export const FIELD_SLUGS = ["username_taken", "last_admin"] as const;

/** One refused field, worded: what the field takes, and its name. */
export interface FieldMessage {
  field: string;
  text: string;
}

function known<T extends string>(list: readonly T[], v: string | null): v is T {
  return v !== null && (list as readonly string[]).includes(v);
}

/** The wording of one refused field of a problem with `status` and `slug`. */
export function fieldMessage(t: Translate, status: number, slug: string | null, field: string): FieldMessage {
  if (status !== 400 && known(FIELD_SLUGS, slug)) return { field, text: t(`cisp.console.validation.slug.${slug}`) };
  if (status === 400 && known(VALIDATION_FIELDS, field)) return { field, text: t(`cisp.console.validation.field.${field}`) };
  return { field, text: t("cisp.console.validation.other") };
}

/**
 * Every refused field of a problem, worded; a 400 that names no field is
 * one line saying the request was refused as malformed. Null when the
 * problem is not a refusal of the request's content (no field, not 400).
 */
export function fieldMessages(t: Translate, status: number, slug: string | null, problem: Problem | null): FieldMessage[] | null {
  const errors = problem?.errors ?? [];
  if (errors.length > 0) return errors.map((e) => fieldMessage(t, status, slug, e.field));
  if (status === 400) return [{ field: "", text: t("cisp.console.validation.refused") }];
  return null;
}

/** The field messages as one sentence for a single message line (the sign-in form). */
export function fieldSentence(messages: readonly FieldMessage[]): string {
  return messages.map((m) => m.text).join(" ");
}
