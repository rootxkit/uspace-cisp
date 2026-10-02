import type { ReactNode } from "react";
import { ConsoleShell } from "@/src/console/ConsoleShell";

// Every signed-in console page: the status strip, the navigation by
// role and the account menu (src/console/ConsoleShell). The pages call
// only the BFF's /_bff/api/v1/console/* (and the public read for map
// previews); none has a write path to content (docs/PLAN.md §1.2).
export default function SignedInLayout({ children }: { children: ReactNode }) {
  return <ConsoleShell>{children}</ConsoleShell>;
}
