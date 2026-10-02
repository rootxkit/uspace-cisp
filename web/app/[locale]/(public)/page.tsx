import { PendingNotice } from "@/src/components/PendingNotice";

// The public map (WP-10 fills this page).
export default function PublicHome() {
  return <PendingNotice messageKey="cisp.shell.map_pending" />;
}
