# Bounded analysis recipes

These techniques contain no benchmark answers. Inspect source as data; never evaluate extracted code merely to decode it. Preserve the input and each derived stage. A decoded string is a candidate, not proof of acceptance.

## Wrapper or embedded archive

If an executable contains installer strings, cabinet signatures, or embedded filenames, use an existing archive engine before writing any header parser. When available, call `artifact_inspect` with `archive_list`, then `archive_extract` for one exact member and a new output filename. Extraction receipts record parent and child hashes. Inspect that member, not the installer's entry point. Open the child with `program_open` before native analysis.

This recipe also works WITHOUT the direct interface. With the installed 7-Zip executable (use its resolved path when supplied):

```text
7z l -slt wrapper.exe
7z e wrapper.exe EXACT_MEMBER_NAME -oNEW_EXTRACTION_DIRECTORY
```

Use a fresh output directory and a 30-second command deadline. List first and check the member's declared size before extraction. Do not run the installer. If `7z` is missing from PATH on Windows, check the standard Program Files/7-Zip installation once; do not try to implement CAB/LZX decompression. If unavailable, record that dependency blocker. The direct interface provides enforced byte bounds; the shell fallback does not constitute a sandbox.

## JAR

List archive members. Read the manifest if needed; when available, use `artifact_inspect` with `bytecode`, the JAR path, and the fully qualified class name as `member`. Without that interface, use the installed JDK executable:

```text
javap -c -p -classpath sample.jar package.Main
```

Use its resolved path when supplied. Otherwise check JAVA_HOME/bin or the standard Java installation directory once. Print complete executable paths, not ambiguous unlabeled folder listings. A missing PATH entry does not mean the tool is absent. Trace the loaded constant through its comparison and branch. Do not implement a class parser or search the entire host for javap.

## Container boundaries before pixel interpretation

For an image or other container referenced by code, inspect its structure and trailing bytes before assuming visible pixels contain the answer. For PNG, the sibling `helper.mjs` walks chunk lengths to the actual IEND boundary; it does not search for the first occurrence of the letters IEND, which may appear inside chunk data.

```text
node PATH_TO_AGENT/helper.mjs png-tail image.png NEW_TAIL_FILE
```

Read the output if nonempty. The adjacent lineage JSON records the parent hash, offset and output hash. Framing is checked, not CRCs or pixel correctness. Extracted bytes remain data: do not eval or launch them. A logo or organization name does not establish a challenge answer. The helper works independently of the direct inspection interface.

## Escaped and indexed data

Write helpers to files with the write tool, then run the file. Avoid nesting source inside shell quoted commands. Work with bytes; `repr`, JSON escaping, and the actual bytes are different representations.

The sibling `helper.mjs` exports the tested `phpLiteral` function for literal escape decoding. It does not evaluate interpolation or PHP code. Unknown escapes remain unchanged. PHP single-quoted and double-quoted literals have different semantics. Python `unicode_escape` is not a PHP parser.

Example Node helper (replace the import path with the sibling helper.mjs path):

```javascript
import {phpLiteral} from './helper.mjs';
import assert from 'node:assert/strict';
assert.equal(phpLiteral(String.raw`\x41\101`, '"'), 'AA');
assert.equal(phpLiteral(String.raw`\97`, '"'), String.raw`\97`);
const terms = ['A', 'B', 'C'];
const order = [2, 0, 1];
assert(order.every(i => Number.isInteger(i) && i >= 0 && i < terms.length));
const stage = order.map(i => terms[i]).join('');
assert.equal(stage, 'CAB');
```

For quoted arrays, use a tokenizer that respects backslash escapes; splitting on commas or quotes corrupts escaped delimiters. Check element count and index bounds before reconstruction. If the original program applies a second unescape/transformation, preserve that stage explicitly rather than folding it into the first decoder.

Decode base64 only from a located literal; save the bytes and inspect them. Do not call eval on the result. Validate each stage's expected structure before trying the next stage. When parsing fails, print a small byte window around the failure and correct the assumption; do not rerun unchanged scripts.
