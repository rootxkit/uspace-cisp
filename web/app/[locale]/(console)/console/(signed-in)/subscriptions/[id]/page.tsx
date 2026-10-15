import { SubscriptionPage } from "@/src/console/SubscriptionsPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.subscriptions");

export default async function Subscription({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SubscriptionPage id={id} />;
}
