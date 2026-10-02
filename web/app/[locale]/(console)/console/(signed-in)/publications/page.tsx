import { Suspense } from "react";
import { PublicationsPage } from "@/src/console/PublicationsPage";

export default function Publications() {
  return (
    <Suspense>
      <PublicationsPage />
    </Suspense>
  );
}
