import { Suspense } from "react";
import { PublicationsPage } from "@/src/console/PublicationsPage";
import { titled } from "@/src/i18n/metadata";

export const generateMetadata = titled("cisp.console.nav.publications");

export default function Publications() {
  return (
    <Suspense>
      <PublicationsPage />
    </Suspense>
  );
}
