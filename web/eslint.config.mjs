import kit from "@rootxkit/uspace-ui/eslint";
import cisp from "./eslint-rules/index.mjs";

export default [
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "next-env.d.ts",
      "test-results/**",
      "playwright-report/**",
      // Files that must fail the project rules (eslint-rules/rules.test.ts).
      "eslint-rules/fixtures/**",
    ],
  },
  ...kit,
  {
    name: "uspace-cisp/web",
    plugins: { cisp },
    rules: {
      "cisp/no-geometry-import": "error",
      "cisp/no-server-business-logic": "error",
      // The kit's route rule, told about the module that configures the
      // BFF; the project rule above is the stricter of the two.
      "uspace-ui/no-business-logic-in-routes": ["error", { allow: ["^@/src/bff/handlers$"] }],
    },
  },
];
