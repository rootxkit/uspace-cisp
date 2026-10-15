import { OverviewPage } from "@/src/console/OverviewPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.overview");

export default function ConsoleHome() {
  return <OverviewPage />;
}
