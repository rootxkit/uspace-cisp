import type { ReactNode } from "react";
import { PublicShell } from "@/src/components/PublicShell";

// The public pages (the map, the USSP list): open, no sign-in, no sidebar.
export default function PublicLayout({ children }: { children: ReactNode }) {
  return <PublicShell>{children}</PublicShell>;
}
