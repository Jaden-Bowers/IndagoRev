export function guidance(file) {
  const ext = String(file).split(".").pop().toLowerCase();
  const common =
    "Choose an operation to resolve a specific question. After an unchanged failure, inspect the error or change the assumption. Write complex helpers to files, test a small input, and use an explicit timeout. Preserve decoded stages as files. Use installed format libraries and archive tools before implementing a format parser. A plausible string alone is not proof of acceptance.";
  const specific = ["py", "js", "html", "php", "txt"].includes(ext)
    ? "Source is available: read it first. Follow the input, transformation and output/acceptance condition. Inspect companion resources when referenced. Prefer a small helper over launching the application. For escaped data, inspect literal bytes and use the source language semantics; do not guess decimal versus octal."
    : ext === "jar"
      ? "For JAR: list archive entries, read the manifest, inspect bytecode with javap. Trace the comparison to its success branch."
      : "For native files: inspect format, resources and embedded archives before decompiling broadly. An installer may wrap the actual target. Use archive extraction where supported. Use Ghidra for pseudocode/xrefs and XAIR for CFG/semantics. Follow a relevant string/import or entry callee. Distinguish file offsets, RVAs and virtual addresses using loader mappings.";
  return specific + "\n" + common;
}
