// What the version page shows of a diff (GET
// /v1/console/publications/{id}/diff): the features grouped by what
// happened to them, each changed one with its JSON Pointer paths. The API
// bounds the lists (at most `limit` features, 200 paths per feature) and
// says when it cut them; the page shows at most PATHS_SHOWN paths per
// feature on first render, and says so whenever anything is not shown,
// whether the API or the page left it out. Nothing is computed here: the
// paths are the API's.
import type { components } from "../api/types";

export type PublicationDiff = components["schemas"]["ConsolePublicationDiff"];
type DiffFeature = PublicationDiff["features"][number];
export type PathChange = components["schemas"]["ConsolePathChange"];

/** Paths shown per feature before "show all". Display-only. */
export const PATHS_SHOWN = 20;

export interface FeatureRow {
  featureId: string;
  op: DiffFeature["op"];
  /** The paths shown (at most `shown` of the API's). */
  paths: PathChange[];
  /** Paths the API sent that are not shown (0 when expanded). */
  hiddenPaths: number;
  /** The API listed only the first 200 of this feature's paths. */
  pathsTruncatedByApi: boolean;
}

export interface DiffView {
  added: FeatureRow[];
  changed: FeatureRow[];
  removed: FeatureRow[];
  /** More features changed than the API listed (`truncated`). */
  featuresTruncated: boolean;
  /** The USSP list's body paths, when the dataset has no features. */
  bodyPaths: PathChange[];
  hiddenBodyPaths: number;
  bodyPathsTruncatedByApi: boolean;
  /** The version diffed against; null for a first version. */
  previousVersion: number | null;
}

function bound(paths: readonly PathChange[] | undefined, shown: number): { paths: PathChange[]; hidden: number } {
  const all = paths ?? [];
  const n = Math.max(0, shown);
  return { paths: all.slice(0, n), hidden: Math.max(0, all.length - n) };
}

/**
 * The diff grouped by operation, each list in the API's order, each path
 * list cut at `shown` (PATHS_SHOWN; Infinity for "show all").
 */
export function diffView(diff: PublicationDiff, shown: number = PATHS_SHOWN): DiffView {
  const rows = diff.features.map((f): FeatureRow => {
    const b = bound(f.paths, shown);
    return {
      featureId: f.feature_id,
      op: f.op,
      paths: b.paths,
      hiddenPaths: b.hidden,
      pathsTruncatedByApi: f.paths_truncated === true,
    };
  });
  const body = bound(diff.body_paths, shown);
  return {
    added: rows.filter((r) => r.op === "added"),
    changed: rows.filter((r) => r.op === "changed"),
    removed: rows.filter((r) => r.op === "removed"),
    featuresTruncated: diff.truncated,
    bodyPaths: body.paths,
    hiddenBodyPaths: body.hidden,
    bodyPathsTruncatedByApi: diff.body_paths_truncated === true,
    previousVersion: diff.previous_version ?? null,
  };
}

/** True when anything of the diff is not on the page. */
export function anythingHidden(v: DiffView): boolean {
  const rows = [...v.added, ...v.changed, ...v.removed];
  return (
    v.featuresTruncated ||
    v.hiddenBodyPaths > 0 ||
    v.bodyPathsTruncatedByApi ||
    rows.some((r) => r.hiddenPaths > 0 || r.pathsTruncatedByApi)
  );
}
