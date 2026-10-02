// T12 (spec 06 §2, 00 §6): no geometry or geodesy in web/. Containment,
// distance, areas and projections are judged once, in Go, on uspace-core;
// the map renders what the API says. The kit's MapLibre components are
// the only way geometry reaches the screen.
import { visitSources } from "./sources.mjs";

/** The package name of a specifier: `@scope/name` or `name`. */
export function packageName(source) {
  if (source.startsWith(".") || source.startsWith("/") || source.startsWith("@/")) return null;
  const parts = source.split("/");
  return source.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? null);
}

export const FORBIDDEN = [
  /^@turf\//,
  /^turf$/,
  /^geojson$/,
  /^proj4$/,
  /^h3-js$/,
  /^@mapbox\//,
  /^geolib$/,
  /^cheap-ruler$/,
  /geodesy/,
];

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Forbids geometry and geodesy libraries in web/ (T12)." },
    schema: [],
    messages: {
      forbidden:
        "'{{source}}' is a geometry or geodesy library. web/ judges nothing: airspace is evaluated in Go on uspace-core, and the map renders the API's answer through the kit.",
    },
  },
  create(context) {
    return visitSources((source, node) => {
      const pkg = packageName(source);
      if (pkg !== null && FORBIDDEN.some((re) => re.test(pkg))) {
        context.report({ node, messageId: "forbidden", data: { source } });
      }
    });
  },
};
