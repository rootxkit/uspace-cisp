import { SubscriptionPage } from "@/src/console/SubscriptionsPage";

export default async function Subscription({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <SubscriptionPage id={id} />;
}
