const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const [worker, fixture, architecture] = process.argv.slice(2);
if (!worker || !fixture) throw Error('worker and source-built managed fixture required');
const sha256 = crypto.createHash('sha256').update(fs.readFileSync(fixture)).digest('hex');
function call(operation, extra = {}) {
  const request = {path: path.resolve(fixture), sha256, operation, output_bytes:65536, wall_ms:5000, ...extra};
  const result = spawnSync(worker, [JSON.stringify(request)], {encoding:'utf8', timeout:10000, maxBuffer:1048576});
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  const body = JSON.parse(result.stdout);
  assert.equal(body.target_executed, false);
  assert.ok(Buffer.byteLength(result.stdout) <= request.output_bytes);
  assert.equal(result.status, body.status === 'completed' ? 0 : body.status === 'partial' ? 3 : 1);
  return body;
}
const inventory = call('inventory');
assert.equal(inventory.status, 'completed');
assert.ok(inventory.method_count >= 3);
assert.equal(inventory.dependency_resolution, 'disabled');
if (architecture === 'x86') { assert.equal(inventory.machine,'I386'); assert.match(inventory.clr_flags,/Requires32Bit/); }
if (architecture === 'x64') { assert.equal(inventory.machine,'Amd64'); assert.equal(inventory.pe_magic,'PE32Plus'); }
const types = call('types', {limit:1});
assert.equal(types.types.length, 1);
assert.equal(types.next_offset, 1);
const methods = call('methods');
const selected = methods.methods.find(method => method.name === 'Select');
assert.ok(selected);
assert.equal(selected.location.address_space, 'managed_metadata');
const decompiled = call('decompile', {token:selected.token});
assert.ok(['partial','completed'].includes(decompiled.status), JSON.stringify(decompiled));
assert.match(decompiled.pseudocode, /Select/);
assert.match(decompiled.pseudocode, /7/);
assert.equal(decompiled.mapping_scope, 'selected_method_token_only');
assert.equal(decompiled.token_mapping_complete, false);
const assembly = call('assembly', {token:selected.token});
assert.equal(assembly.status,'completed',JSON.stringify(assembly));
assert.match(assembly.assembly,/IL_0000/);
assert.ok(assembly.tokens.some(token=>token.kind==='il_offset_reference' && token.is_definition));
for (const token of assembly.tokens) {
  assert.equal(assembly.assembly.slice(token.start_utf16, token.end_utf16), token.text);
  if (token.kind === 'il_offset_reference') assert.equal(token.location.address_space, 'managed_il:' + selected.token);
}
assert.equal(call('methods', {offset:1000000}).methods.length, 0);
assert.equal(call('decompile', {token:'0x02000001'}).status, 'failed');
assert.equal(call('inventory', {sha256:'0'.repeat(64)}).status, 'failed');
assert.equal(call('inventory', {limit:129}).status, 'failed');
const bounded = call('decompile', {token:selected.token, output_bytes:4096});
assert.ok(['partial','completed'].includes(bounded.status));
console.log(JSON.stringify({status:'passed',fixture_sha256:sha256,method:selected.token,worker}));
