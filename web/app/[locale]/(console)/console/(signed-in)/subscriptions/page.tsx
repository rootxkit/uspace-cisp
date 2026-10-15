import { SubscriptionsPage } from "@/src/console/SubscriptionsPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.subscriptions");

export default function Subscriptions() {
  return <SubscriptionsPage />;
}
