import type { NextRequest } from "next/server";
import { bff } from "@/src/bff/handlers";

export const dynamic = "force-dynamic";

function proxy(req: NextRequest): Promise<Response> {
  return bff().proxy(req);
}

export { proxy as GET, proxy as HEAD, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE };
