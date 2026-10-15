import { AuditPage } from "@/src/console/AuditPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.audit");

export default function Audit() {
  return <AuditPage />;
}
