// Shared by the two project rules: every static module specifier in a
// file (import, export ... from, import(), require()).
export function visitSources(visit) {
  const fromSource = (node) => {
    const s = node.source;
    if (s && s.type === "Literal" && typeof s.value === "string") visit(s.value, node);
  };
  return {
    ImportDeclaration: fromSource,
    ExportNamedDeclaration: fromSource,
    ExportAllDeclaration: fromSource,
    ImportExpression: fromSource,
    CallExpression(node) {
      if (node.callee.type !== "Identifier" || node.callee.name !== "require") return;
      const a = node.arguments[0];
      if (a && a.type === "Literal" && typeof a.value === "string") visit(a.value, node);
    },
  };
}

/** The file name with forward slashes, so path rules read the same on Windows. */
export function posixFilename(context) {
  return context.filename.replaceAll("\\", "/");
}
