import noGeometryImport from "./no-geometry-import.mjs";
import noServerBusinessLogic from "./no-server-business-logic.mjs";

/** This repository's two web/ rules, registered as `cisp/...`. */
export default {
  meta: { name: "uspace-cisp-web" },
  rules: {
    "no-geometry-import": noGeometryImport,
    "no-server-business-logic": noServerBusinessLogic,
  },
};
