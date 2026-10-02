import type { NextRequest } from "next/server";
import { bff } from "@/src/bff/handlers";

export const dynamic = "force-dynamic";

export function POST(req: NextRequest): Promise<Response> {
  return bff().logout(req);
}
