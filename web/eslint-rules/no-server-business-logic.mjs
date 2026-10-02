// Spec 00 §6.2 and 07 KT-3: Next.js renders, and its only server code is
// the BFF. Route handlers live under app/%5Fbff/ (the URL /_bff/*; the App
// Router ignores folders that start with "_") and, with the module that
// configures them (src/bff/), import only the kit's BFF helpers,
// next/server and the generated API types. No other app/**/route.ts may
// exist.
import { posixFilename, visitSources } from "./sources.mjs";

const BFF_ROUTE = /(?:^|\/)app\/(?:_bff|%5[Ff]bff)\//;
const BFF_MODULE = /(?:^|\/)src\/bff\/[^/]+$/;
const ROUTE_FILE = /(?:^|\/)app\/(?:.*\/)?route\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.test\.[cm]?[jt]sx?$/;

const BFF_ALLOWED = [
  /^@rootxkit\/uspace-ui\/auth\/server$/,
  /^next\/server(?:\.js)?$/,
  /^@\/src\/api\/types$/,
];
// A route file may also import the one module that configures the kit.
const ROUTE_ALLOWED = [...BFF_ALLOWED, /^@\/src\/bff\/handlers$/];

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Keeps server-side code to the BFF's three routes (00 §6.2, 07 KT-3)." },
    schema: [],
    messages: {
      forbidden:
        "'{{source}}' is not allowed here. The BFF imports only @rootxkit/uspace-ui/auth/server, next/server and src/api/types; business logic belongs to the CISP's API.",
      route: "A route handler outside app/%5Fbff/ (the /_bff/* routes). web/ has no other server routes.",
    },
  },
  create(context) {
    const file = posixFilename(context);
    if (TEST_FILE.test(file)) return {};
    const isBffRoute = BFF_ROUTE.test(file);
    if (ROUTE_FILE.test(file) && !isBffRoute) {
      return {
        Program(node) {
          context.report({ node, messageId: "route" });
        },
      };
    }
    const allowed = isBffRoute ? ROUTE_ALLOWED : BFF_MODULE.test(file) ? BFF_ALLOWED : null;
    if (allowed === null) return {};
    return visitSources((source, node) => {
      if (!allowed.some((re) => re.test(source))) {
        context.report({ node, messageId: "forbidden", data: { source } });
      }
    });
  },
};
