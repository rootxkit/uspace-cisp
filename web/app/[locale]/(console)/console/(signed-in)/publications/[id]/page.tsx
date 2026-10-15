import { VersionPage } from "@/src/console/VersionPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.publications");

export default async function PublicationVersion({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <VersionPage id={id} />;
}
