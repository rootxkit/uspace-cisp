// The words and tones of the console's state badges: a delivery's state,
// a subscription's status and a restriction's state, as the API names
// them. A state the API adds later is shown by its own name with the
// "unknown" tone, never as one of these (the enumerations are open within
// v1 for consumers that read them).
import type { components } from "../api/types";

export type DeliveryState = components["schemas"]["Delivery"]["state"];
export type SubscriptionStatus = components["schemas"]["Subscription"]["status"];
export type RestrictionState = components["schemas"]["RestrictionHead"]["state"];

/**
 * - ok: nothing to do (delivered, active)
 * - pending: on its way (queued, delivering, pending verification, planned)
 * - attention: an operator should look (failed, suspended)
 * - ended: over, kept for the record (expired, deleted, ended, cancelled)
 * - unknown: a value this console does not know
 */
export type Tone = "ok" | "pending" | "attention" | "ended" | "unknown";

export interface BadgeSpec {
  /** The catalogue key, or null for a value shown as the API sent it. */
  labelKey: string | null;
  tone: Tone;
}

export const DELIVERY_STATES: readonly DeliveryState[] = ["queued", "delivering", "delivered", "failed", "expired"];

const DELIVERY_TONE: Record<DeliveryState, Tone> = {
  queued: "pending",
  delivering: "pending",
  delivered: "ok",
  failed: "attention",
  expired: "ended",
};

export const SUBSCRIPTION_STATUSES: readonly SubscriptionStatus[] = ["pending_verification", "active", "suspended", "deleted"];

const SUBSCRIPTION_TONE: Record<SubscriptionStatus, Tone> = {
  pending_verification: "pending",
  active: "ok",
  suspended: "attention",
  deleted: "ended",
};

export const RESTRICTION_STATES: readonly RestrictionState[] = ["planned", "active", "ended", "cancelled"];

const RESTRICTION_TONE: Record<RestrictionState, Tone> = {
  planned: "pending",
  active: "attention",
  ended: "ended",
  cancelled: "ended",
};

function spec<S extends string>(tones: Record<S, Tone>, prefix: string, v: string): BadgeSpec {
  return Object.hasOwn(tones, v)
    ? { labelKey: `${prefix}.${v}`, tone: tones[v as S] }
    : { labelKey: null, tone: "unknown" };
}

export function deliveryBadge(state: string): BadgeSpec {
  return spec(DELIVERY_TONE, "cisp.console.delivery.state", state);
}

export function subscriptionBadge(status: string): BadgeSpec {
  return spec(SUBSCRIPTION_TONE, "cisp.console.subscription.status", status);
}

export function restrictionBadge(state: string): BadgeSpec {
  return spec(RESTRICTION_TONE, "cisp.console.restriction.state", state);
}

/** The badge's classes per tone (the kit's tokens). Display-only. */
export const TONE_CLASS: Record<Tone, string> = {
  ok: "border-[var(--us-border)] bg-[var(--us-surface-raised)] text-[var(--us-text)]",
  pending: "border-[var(--us-border)] bg-[var(--us-surface)] text-[var(--us-text-muted)]",
  attention: "border-[var(--us-danger)] bg-[var(--us-surface-raised)] text-[var(--us-danger)] font-semibold",
  ended: "border-[var(--us-border)] bg-[var(--us-surface)] text-[var(--us-text-muted)]",
  unknown: "border-dashed border-[var(--us-border)] text-[var(--us-text)]",
};
