import { PendingNotice } from "@/src/components/PendingNotice";

// The console (WP-11 fills this route group).
export default function ConsoleHome() {
  return <PendingNotice messageKey="cisp.console.pending" />;
}
