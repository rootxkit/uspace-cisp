// The frame's two pure helpers: the top bar's pill from the stream, and
// the same page under the other language's prefix.
import { describe, expect, it } from "vitest";
import { pathInLang } from "../components/Providers";
import { pillState } from "./ConsoleShell";

describe("the top bar's pill", () => {
  it("is live while the last frame is within the server's stale_after_s", () => {
    expect(pillState({ connection: "live", staleAfterS: 10 }, 10)).toBe("live");
  });

  it("is stale once the last frame is older than the server's stale_after_s (the pair)", () => {
    expect(pillState({ connection: "live", staleAfterS: 10 }, 11)).toBe("stale");
  });

  it("never calls a feed stale on a bound the server has not sent", () => {
    expect(pillState({ connection: "live", staleAfterS: null }, 3600)).toBe("live");
    expect(pillState({ connection: "live", staleAfterS: 10 }, null)).toBe("live");
  });

  it("says connecting and down as the feed does", () => {
    expect(pillState({ connection: "connecting", staleAfterS: 10 }, 99)).toBe("connecting");
    expect(pillState({ connection: "down", staleAfterS: 10 }, 99)).toBe("down");
  });
});

describe("the language switch's address", () => {
  it("swaps the prefix and keeps the rest of the path", () => {
    expect(pathInLang("/ka/console/publications", "en")).toBe("/en/console/publications");
    expect(pathInLang("/en", "ka")).toBe("/ka");
  });

  it("leaves a path segment that only starts like a language alone", () => {
    expect(pathInLang("/kaz/x", "en")).toBe("/en/kaz/x");
  });
});
