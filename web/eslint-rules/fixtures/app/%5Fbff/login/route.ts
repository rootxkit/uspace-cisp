// Must fail cisp/no-server-business-logic: the BFF holds no database.
import { Pool } from "pg";

export function POST(): Response {
  return new Response(String(typeof Pool));
}
