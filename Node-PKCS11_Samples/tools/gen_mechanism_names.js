#!/usr/bin/env node
/** One-shot: convert lunacm "partition showmechanism" text dump -> lib/mechanism_names.js */
"use strict";
const fs = require("fs");
const path = require("path");

const src = process.argv[2];
if (!src) {
  console.error("Usage: node tools/gen_mechanism_names.js <lunacm-dump.txt>");
  process.exit(1);
}
const text = fs.readFileSync(src, "utf8");
const re = /^\s*0x([0-9a-fA-F]+)\s+-\s+(CKM_\S+)/gm;
const map = new Map();
let m;
while ((m = re.exec(text))) {
  map.set(parseInt(m[1], 16), m[2]);
}
const ids = [...map.keys()].sort((a, b) => a - b);
const lines = [
  '"use strict";',
  "",
  "/**",
  " * CKM_* names graphene-pk11 does not resolve.",
  ' * Generated from Luna lunacm: partition showmechanism',
  " */",
  "const NAMES = {",
];
for (const id of ids) {
  lines.push(`  0x${id.toString(16)}: "${map.get(id)}",`);
}
lines.push(
  "};",
  "",
  "let pkcs11ByValue = null;",
  "function pkcs11Map() {",
  "  if (pkcs11ByValue) return pkcs11ByValue;",
  "  pkcs11ByValue = Object.create(null);",
  "  try {",
  '    const pkcs11 = require("pkcs11js");',
  "    for (const k of Object.keys(pkcs11)) {",
  '      if (k.startsWith("CKM_") && typeof pkcs11[k] === "number") {',
  "        pkcs11ByValue[pkcs11[k] >>> 0] = k;",
  "      }",
  "    }",
  "  } catch (_) {}",
  "  return pkcs11ByValue;",
  "}",
  "",
  "/** Printable name without CKM_ prefix (graphene style). Hex fallback. */",
  "function mechanismName(type, grapheneName) {",
  "  const t = Number(type) >>> 0;",
  "  const fromTable = NAMES[t];",
  '  if (fromTable) return fromTable.replace(/^CKM_/, "");',
  "  const fromPkcs11 = pkcs11Map()[t];",
  '  if (fromPkcs11) return fromPkcs11.replace(/^CKM_/, "");',
  '  const g = grapheneName == null ? "" : String(grapheneName);',
  '  if (g && g !== "unknown") return g;',
  '  return "0x" + t.toString(16);',
  "}",
  "",
  "module.exports = { mechanismName, NAMES };",
  ""
);
const out = path.join(__dirname, "..", "lib", "mechanism_names.js");
fs.writeFileSync(out, lines.join("\n"));
console.log("Wrote", out, "(" + map.size + " names)");
