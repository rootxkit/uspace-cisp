import { describe, expect, it } from "vitest";
import en from "../i18n/en.json";
import ka from "../i18n/ka.json";
import {
  DELIVERY_STATES,
  deliveryBadge,
  RESTRICTION_STATES,
  restrictionBadge,
  SUBSCRIPTION_STATUSES,
  subscriptionBadge,
  TONE_CLASS,
} from "./badges";

const catalogues: Record<string, string>[] = [en, ka];

describe("delivery state badges", () => {
  it("each delivery state has its word in both languages and its tone", () => {
    for (const s of DELIVERY_STATES) {
      const b = deliveryBadge(s);
      expect(b.labelKey, s).toBe(`cisp.console.delivery.state.${s}`);
      for (const c of catalogues) expect(c[b.labelKey ?? ""], s).toBeTruthy();
      expect(TONE_CLASS[b.tone]).toBeTruthy();
    }
  });

  it("a failed delivery calls for attention, a delivered one does not", () => {
    expect(deliveryBadge("failed").tone).toBe("attention");
    expect(deliveryBadge("delivered").tone).toBe("ok");
    expect(deliveryBadge("queued").tone).toBe("pending");
    expect(deliveryBadge("delivering").tone).toBe("pending");
    expect(deliveryBadge("expired").tone).toBe("ended");
  });

  it("a state the console does not know is shown as sent, never as a known one", () => {
    expect(deliveryBadge("bounced")).toEqual({ labelKey: null, tone: "unknown" });
    // An inherited property name is not a state.
    expect(deliveryBadge("constructor")).toEqual({ labelKey: null, tone: "unknown" });
  });

  it("the delivery states are the API's enumeration", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const spec = readFileSync(fileURLToPath(new URL("../../../api/openapi.yaml", import.meta.url)), "utf8");
    const block = spec.slice(spec.indexOf("\n    Delivery:\n"), spec.indexOf("\n    DeliveryAttempt:\n"));
    expect(block).toContain(`enum: [${DELIVERY_STATES.join(", ")}]`);
  });
});

describe("subscription and restriction badges", () => {
  it("every status and state has its word in both languages", () => {
    for (const s of SUBSCRIPTION_STATUSES) {
      const k = subscriptionBadge(s).labelKey ?? "";
      for (const c of catalogues) expect(c[k], s).toBeTruthy();
    }
    for (const s of RESTRICTION_STATES) {
      const k = restrictionBadge(s).labelKey ?? "";
      for (const c of catalogues) expect(c[k], s).toBeTruthy();
    }
  });

  it("a suspended subscription calls for attention, an active one does not", () => {
    expect(subscriptionBadge("suspended").tone).toBe("attention");
    expect(subscriptionBadge("active").tone).toBe("ok");
    expect(subscriptionBadge("gone").tone).toBe("unknown");
  });
});
