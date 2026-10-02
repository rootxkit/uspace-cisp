// No display string outside the ka/en catalogues (CLAUDE.md rule 9): no
// JSX text node and no string-literal accessible label in a page or a
// component. The kit's ESLint config has no such rule, so this test reads
// the TSX with the TypeScript parser.
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LETTER = /\p{L}/u;
const LABEL_ATTRS = new Set(["aria-label", "aria-description", "title", "alt", "placeholder", "label"]);

/** "file:line text" for every hardcoded display string in `source`. */
export function literals(file: string, source: string): string[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const out: string[] = [];
  const at = (n: ts.Node) => `${file}:${sf.getLineAndCharacterOfPosition(n.getStart()).line + 1}`;
  const visit = (n: ts.Node) => {
    if (ts.isJsxText(n) && LETTER.test(n.text)) out.push(`${at(n)} ${n.text.trim()}`);
    if (ts.isJsxAttribute(n) && LABEL_ATTRS.has(n.name.getText(sf)) && n.initializer !== undefined) {
      const init = n.initializer;
      const text = ts.isStringLiteral(init)
        ? init.text
        : ts.isJsxExpression(init) && init.expression !== undefined && ts.isStringLiteralLike(init.expression)
          ? init.expression.text
          : null;
      if (text !== null && LETTER.test(text)) out.push(`${at(n)} ${n.name.getText(sf)}="${text}"`);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

function tsxFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) return tsxFiles(p);
    return name.endsWith(".tsx") && !name.endsWith(".test.tsx") ? [p] : [];
  });
}

describe("display strings", () => {
  it("the scan finds a hardcoded text node and label", () => {
    expect(literals("x.tsx", `export const X = () => <p aria-label="Zones">Hello</p>;`)).toEqual([
      "x.tsx:1 aria-label=\"Zones\"",
      "x.tsx:1 Hello",
    ]);
    expect(literals("x.tsx", `export const X = () => <p title={"ზონა"}>{t("k")}</p>;`)).toHaveLength(1);
  });

  it("the scan passes translated text, punctuation and empty alt", () => {
    expect(literals("x.tsx", `export const X = () => <p aria-label={t("k")}>{t("k")} · <img alt="" /></p>;`)).toEqual([]);
  });

  it("app/ and src/ hold none", () => {
    const files = [...tsxFiles(path.join(web, "app")), ...tsxFiles(path.join(web, "src"))];
    expect(files.length).toBeGreaterThan(3);
    const found = files.flatMap((f) => literals(path.relative(web, f), readFileSync(f, "utf8")));
    expect(found).toEqual([]);
  });
});
