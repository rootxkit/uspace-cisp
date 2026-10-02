// Must fail cisp/no-geometry-import: the web judges nothing.
import booleanPointInPolygon from "@turf/boolean-point-in-polygon";

export default function Page() {
  return <p>{String(typeof booleanPointInPolygon)}</p>;
}
