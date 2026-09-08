// Offline callback contract checks. No Frida attachment or sockets are opened.
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../workers/frida/recipes.js'), 'utf8');
class Pointer {
  constructor(value, bytes) { this.value = BigInt.asUintN(64, BigInt(value)); this.bytes = bytes || Buffer.alloc(256, 0x41); }
  toString() { return '0x' + this.value.toString(16); }
  toInt32() { return Number(BigInt.asIntN(32, this.value)); }
  toUInt32() { return Number(BigInt.asUintN(32, this.value)); }
  isNull() { return this.value === 0n; }
  equals(other) { return this.value === other.value; }
  add(size) { return new Pointer(this.value + BigInt(size)); }
  compare(other) { return this.value < other.value ? -1 : this.value > other.value ? 1 : 0; }
  readByteArray(size) { assert(size <= this.bytes.length); return Uint8Array.from(this.bytes.subarray(0, size)).buffer; }
  readU32() { return this.bytes.readUInt32LE(0); }
}
function setup(platform, budget = 10000) {
  const hooks = new Map(), exports = new Map(), events = [];
  function exported(api) {
    if (!exports.has(api)) { const address = new Pointer(0x1100 + exports.size * 16); address.api = api; exports.set(api, address); }
    return exports.get(api);
  }
  const module = {base: new Pointer(0x1000), size: 4096, path: 'source-backed-mock', findExportByName: exported};
  vm.runInNewContext(source, {
    recipe: 'network', budget, ptr: n => new Pointer(n),
    send: record => events.push(JSON.parse(JSON.stringify(record))),
    Process: {platform, id: 123, arch: 'x64', getCurrentThreadId: () => 1, enumerateModules: () => [module],
      attachThreadObserver: observer => observer.onAdded({id: 1}), attachModuleObserver: observer => observer.onAdded(module)},
    Module: {findGlobalExportByName: exported},
    Interceptor: {attach: (address, listener) => { hooks.set(address.api, listener); return {detach() {}}; }}
  }, {timeout: 1000});
  function call(api, args, result, between) {
    const context = {threadId: 1, returnAddress: new Pointer(0x2000), errno: 115, lastError: 123};
    const pointers = Array.from({length: 6}, (_, i) => args[i] instanceof Pointer ? args[i] : new Pointer(args[i] || 0));
    hooks.get(api).onEnter.call(context, pointers);
    if (between) between();
    hooks.get(api).onLeave.call(context, new Pointer(result));
    return events.filter(e => e.call_id === context.call && e.kind === 'api_leave').at(-1);
  }
  return {events, call};
}
for (const platform of ['windows', 'linux']) {
  const {events, call} = setup(platform);
  const first = call('socket', [2, 1, 0], 7).socket;
  assert.equal(first.creation_observed, true);
  assert.equal(first.identity_complete, false);
  const invalid = call('connect', [-1, 0, 0], -1);
  assert.equal(invalid.socket, undefined, 'invalid descriptor cannot create a socket identity');
  const sent = call('send', [7, new Pointer(0x3000), 128], 5);
  const entered = events.filter(e => e.kind === 'api_enter' && e.call_id === sent.call_id)[0];
  assert.equal(entered.socket.instance, first.instance);
  assert.equal(entered.buffer_hex.length, 128);
  assert.equal(entered.buffer_truncated, true);
  assert.equal(sent.transferred_bytes, 5);
  assert.equal(sent.delivery_proven, false);
  const read = call('recv', [7, new Pointer(0x3000), 2], 5);
  assert.equal(read.buffer_hex.length, 4, 'read capture cannot exceed supplied buffer length');
  assert.equal(read.buffer_truncated, true);
  const pending = call('connect', [7, new Pointer(0x4000), 16], -1);
  assert.equal(pending.network_outcome, 'failed_or_pending');
  if (platform === 'windows') assert.match(pending.error_semantics, /not WSAGetLastError/);
  if (platform === 'windows') {
    const error = call('send', [7, new Pointer(0x3000), 0xffffffff], 0xffffffff);
    assert.equal(error.network_outcome, 'transfer_api_error', 'zero-extended Winsock int -1 is not a positive byte count');
    const entry = events.filter(e => e.kind === 'api_enter' && e.call_id === error.call_id)[0];
    assert.equal(entry.buffer_hex, undefined, 'negative Winsock length is not read');
  }
  const close = platform === 'windows' ? 'closesocket' : 'close';
  assert.equal(call(close, [7], 0).socket_event, 'close_api_success');
  const second = call('socket', [2, 1, 0], 7).socket;
  assert.notEqual(second.instance, first.instance, 'handle reuse creates a new observation identity');
  let replacement;
  const race = call(close, [7], 0, () => { replacement = call('socket', [2, 1, 0], 7).socket; });
  assert.equal(race.socket_generation_race, true);
  assert.equal(call('send', [7, new Pointer(0x3000), 1], 1).socket.instance, replacement.instance);
  const size = Buffer.alloc(4); size.writeUInt32LE(256);
  const accepted = call('accept', [7, new Pointer(0x4000), new Pointer(0x5000, size)], 8);
  assert.equal(accepted.socket.origin, 'accepted');
  assert.equal(accepted.listener_socket.instance, replacement.instance);
  assert.equal(accepted.sockaddr_hex.length, 256);
  assert.equal(accepted.sockaddr_truncated, true);
  const tinyLength=Buffer.alloc(4);tinyLength.writeUInt32LE(4);
  const tinyAddress=new Pointer(0x4000,Buffer.alloc(4,0x41));
  const grown=call('accept',[7,tinyAddress,new Pointer(0x5000,tinyLength)],9,()=>tinyLength.writeUInt32LE(256));
  assert.equal(grown.sockaddr_hex.length,8,'accept capture respects entry capacity when returned length grows');
  assert.equal(grown.sockaddr_capacity,4);
  assert.equal(grown.sockaddr_returned_length,256);
  assert.equal(grown.sockaddr_truncated,true);
  tinyLength.writeUInt32LE(4);
  const datagram=call('recvfrom',[7,new Pointer(0x3000),1,0,tinyAddress,new Pointer(0x5000,tinyLength)],1,()=>tinyLength.writeUInt32LE(256));
  assert.equal(datagram.sockaddr_hex.length,8,'recvfrom address capture respects entry capacity');
  if(platform==='windows') {
    tinyLength.writeUInt32LE(0xffffffff);
    const invalidCapacity=call('accept',[7,tinyAddress,new Pointer(0x5000,tinyLength)],10,()=>tinyLength.writeUInt32LE(4));
    assert.equal(invalidCapacity.sockaddr_hex,undefined,'negative entry capacity is never converted into a large unsigned read');
    assert.equal(invalidCapacity.sockaddr_read_status,'entry_capacity_unavailable');
    const invalidConnect=call('connect',[7,tinyAddress,0xffffffff],-1);
    const invalidEntry=events.find(e=>e.kind==='api_enter'&&e.call_id===invalidConnect.call_id);
    assert.equal(invalidEntry.sockaddr_hex,undefined,'negative input address length is not read');
  }
  const inherited = call('connect', [99, new Pointer(0x4000), 16], -1);
  assert.equal(inherited.socket.origin, 'first_observed');
  assert.equal(inherited.socket.creation_observed, false);
  assert.equal(inherited.socket.validity, 'candidate_handle_only');
  if (platform === 'windows') assert.match(call('WSARecv', [7, 0, 0, 0], 0).network_completeness, /not modeled/);
  assert.equal(call('socket', [2, 1, 0], -1).socket_event, 'creation_failed');
  let capped;
  for (let i = 1000; i < 2100; ++i) capped = call('socket', [2, 1, 0], i);
  assert.equal(capped.socket.instance, null);
  assert.equal(capped.socket.origin, 'tracking_limit');
}
const limited = setup('linux', 2);
assert.equal(limited.events.filter(e => e.kind === 'collection_limit').length, 1);
limited.call('socket', [2, 1, 0], 3);
assert.equal(limited.events.filter(e => e.kind === 'api_enter' || e.kind === 'api_leave').length, 0);
console.log(JSON.stringify({status: 'passed', platforms: ['windows', 'linux'], target_execution: false,
  checks: 'socket generations, reuse/races, bounded bytes/state, incomplete/pending semantics, collection limit'}));
