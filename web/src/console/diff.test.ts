import { describe, expect, it } from "vitest";
import { anythingHidden, diffView, PATHS_SHOWN, type PathChange, type PublicationDiff } from "./diff";

const publication: PublicationDiff["publication"] = {
  id: "pub-1",
  dataset: "zones",
  version: 2,
  publisher: "authority-01",
  received_at: "2026-10-01T08:00:00Z",
  feature_count: 3,
  added: 1,
  changed: 1,
  removed: 1,
  reason: "publication",
};

function paths(n: number): PathChange[] {
  return Array.from({ length: n }, (_, i) => ({ path: `/properties/name/${i}`, op: "changed" as const }));
}

function diff(over: Partial<PublicationDiff> = {}): PublicationDiff {
  return {
    publication,
    previous_version: 1,
    truncated: false,
    features: [
      { feature_id: "NEW0001", op: "added" },
      { feature_id: "CHG0001", op: "changed", paths: paths(3) },
      { feature_id: "OLD0001", op: "removed" },
    ],
    ...over,
  };
}

describe("the diff renderer", () => {
  it("groups the features by operation in the API's order", () => {
    const v = diffView(diff());
    expect(v.added.map((r) => r.featureId)).toEqual(["NEW0001"]);
    expect(v.changed.map((r) => r.featureId)).toEqual(["CHG0001"]);
    expect(v.removed.map((r) => r.featureId)).toEqual(["OLD0001"]);
    expect(v.previousVersion).toBe(1);
    expect(v.changed[0]?.paths).toHaveLength(3);
  });

  it("a short path list is shown whole and nothing is said to be hidden", () => {
    const v = diffView(diff());
    expect(v.changed[0]?.hiddenPaths).toBe(0);
    expect(anythingHidden(v)).toBe(false);
  });

  it("a long path list is bounded at PATHS_SHOWN and says how many are not shown", () => {
    const v = diffView(diff({ features: [{ feature_id: "CHG0001", op: "changed", paths: paths(PATHS_SHOWN + 7) }] }));
    expect(v.changed[0]?.paths).toHaveLength(PATHS_SHOWN);
    expect(v.changed[0]?.hiddenPaths).toBe(7);
    expect(anythingHidden(v)).toBe(true);
  });

  it("exactly PATHS_SHOWN paths hide nothing (the bound's edge)", () => {
    const v = diffView(diff({ features: [{ feature_id: "CHG0001", op: "changed", paths: paths(PATHS_SHOWN) }] }));
    expect(v.changed[0]?.hiddenPaths).toBe(0);
  });

  it("show all lifts the page's bound but not the API's notice", () => {
    const v = diffView(
      diff({ features: [{ feature_id: "CHG0001", op: "changed", paths: paths(200), paths_truncated: true }] }),
      Number.POSITIVE_INFINITY,
    );
    expect(v.changed[0]?.paths).toHaveLength(200);
    expect(v.changed[0]?.hiddenPaths).toBe(0);
    expect(v.changed[0]?.pathsTruncatedByApi).toBe(true);
    expect(anythingHidden(v)).toBe(true);
  });

  it("the API's truncated feature list is said (and its absence is not)", () => {
    expect(diffView(diff({ truncated: true })).featuresTruncated).toBe(true);
    expect(anythingHidden(diffView(diff({ truncated: true })))).toBe(true);
    expect(diffView(diff()).featuresTruncated).toBe(false);
  });

  it("the USSP list's body paths are bounded the same way", () => {
    const v = diffView(diff({ features: [], body_paths: paths(PATHS_SHOWN + 1), body_paths_truncated: true }));
    expect(v.bodyPaths).toHaveLength(PATHS_SHOWN);
    expect(v.hiddenBodyPaths).toBe(1);
    expect(v.bodyPathsTruncatedByApi).toBe(true);
  });

  it("a first version has no predecessor", () => {
    const d = diff();
    delete d.previous_version;
    expect(diffView(d).previousVersion).toBeNull();
  });
});
