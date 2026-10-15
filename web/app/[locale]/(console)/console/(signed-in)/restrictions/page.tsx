import { RestrictionsPage } from "@/src/console/RestrictionsPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.restrictions");

export default function Restrictions() {
  return <RestrictionsPage />;
}
