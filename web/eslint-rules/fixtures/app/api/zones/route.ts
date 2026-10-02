// Must fail cisp/no-server-business-logic: no route outside app/%5Fbff/.
export function GET(): Response {
  return new Response(null, { status: 204 });
}
