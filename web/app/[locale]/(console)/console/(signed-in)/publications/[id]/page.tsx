import { VersionPage } from "@/src/console/VersionPage";

export default async function PublicationVersion({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <VersionPage id={id} />;
}
