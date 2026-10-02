import { PublicMap } from "@/src/public/PublicMap";

// The public zone map (WP-10): /public/v1/* and WS /v1/stream only.
export default function PublicHome() {
  return <PublicMap />;
}
