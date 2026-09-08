# Offline network evidence

The `wireshark` adapter uses a privately bundled upstream TShark 4.6.8 worker:
the official Windows package and a source-built native Linux offline profile. The
native application remains C++20; this is an upstream native dissector integration,
not a new PCAP or protocol semantic stack.

Import a capture as an ordinary immutable artifact, then query:

```
indago target import --project case --file capture.pcapng
indago query --project case --backend wireshark --operation packets --max-items 8
```

`analyze --backend wireshark` selects the same packet operation. The other explicit
adapter presets are ILSpy inventory/types/methods, capa capabilities, FLOSS strings,
and LIEF inventory/sections/libraries. Optional adapters are not implicitly added
to the default native-analysis baseline.

PCAP/PCAPNG only, <=16 MiB input, <=64 displayed packets per page, offset <=4096,
<=4 MiB output, <=60 seconds or lower requested wall limit. Paging replays the
bounded prefix through the upstream dissectors to retain preceding flow context;
it is not an indexed random-access capture database. One lookahead frame determines
whether another page exists. Large packets can exceed output limits; increase the
budget when the first selected packet cannot fit. Cancellation kills the worker
tree. No OS memory quota, filesystem quota or hostile-parser sandbox is claimed.

The same-executable intermediary sets fresh empty personal/global plugin,
preference and data directories before launching TShark. It supplies only fixed
offline arguments, disables name resolution, and accepts no display-filter code,
Lua script, extension argument, decryption-key path, capture interface or executable
override from the caller. On Windows the upstream Lua runtime is present but no Lua scripts
or external native plugins are loaded. `enable_lua=false` triggers an upstream
cleanup crash in the pinned Windows package; the empty-profile approach passes
preflight without patching the DLL. Details are in `vendor/wireshark/PROVENANCE.md`.
Linux compiles Lua, external plugins and libpcap out entirely. Its optional feature
profile excludes GnuTLS/Kerberos, nghttp2/3, brotli/LZ4/Snappy; consult the bundled
`network/build-profile.txt` and build recipe rather than assuming feature parity.
It statically links analysis libraries but still requires its host glibc baseline.

Native packet JSON and raw-field mappings are retained, with duplicate JSON keys
merged by upstream's explicit option. Indexed packet identities use the immutable
capture hash and native frame ordinal in `capture_frame` address space. Frame/data-
source-relative raw offsets are **not** converted into file offsets. The native
record offset is retained separately; it need not point to the first captured byte.
Upstream's timestamp text is preserved verbatim: this version encodes
`frame.time_epoch` as ISO UTC text. Container timestamp resolution is not separately
exposed yet. These distinctions avoid inventing source mappings or precision.

Each page also projects explicit upstream `tcp.stream`/`udp.stream` fields into
`streams` and packet `stream_refs`, indexed as `packet_stream` entities with
`native_stream_member` relations. IDs include capture hash, transport, native
ordinal and dissection-profile provenance; they remain stable across pages of the
same profile. They are **not** endpoint-derived connection incarnations or process
identities. Membership covers only returned packets, never a complete stream.
Pointers lead back to the exact native stream field. Ambiguous repeated protocol
layers/stream values stay in native JSON and set `stream_projection_partial`;
the adapter does not guess their association or assign a stream a program address.

Bounded frame references project upstream `tcp.segment`, `tcp.reassembled_in`
and `tcp.analysis.acks_frame` assertions. `native_tcp_segment_source`,
`native_tcp_reassembled_in` and `native_tcp_ack` index relations retain exact native
field pointers and capture-frame anchors. References outside the returned page
keep their target location without inventing an indexed target entity. At most
64 references per packet and 1024 visited JSON nodes/depth 12 are projected;
omissions are flagged and the full bounded upstream JSON remains available.
Reassembled raw-field offsets stay in their upstream data source, not the capture
file. A source-generated split HTTP request exercises the upstream reassembly and
links, including a page containing only its final frame. This is not an independent
TCP reassembler or a claim of complete/delivered application traffic.

Packet presence is not proof of delivery, a complete network capture, a process
identity, or application behavior. Process/API joins, reliable flow incarnation,
explicit reassembly provenance, clock alignment, stream windows and lab-scoped
live capture remain work. No sample-derived destination is contacted. No capture
driver, CA, interface listener, remote service, or system Wireshark is installed.
The worker is not an OS egress-isolation boundary even though requested name
resolution and capture are disabled.

Source-generated PCAP and PCAPNG microfixtures pass direct upstream checks, including
frame-byte identity, interface identity and nine-digit timestamp preservation.
Native service/index/harness checks pass on Windows and Linux, with paging,
truncation and caller-profile isolation. Fabricated split-HTTP checks pass direct
upstream and native CLI/index paths on both platforms. Extensive parser fuzzing,
reproducible-build qualification and full transitive DLL/source/license delivery
remain release qualification gates.

Primary references: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html),
[frame fields and offsets](https://github.com/wireshark/wireshark/blob/v4.6.8/epan/dissectors/packet-frame.c),
[Lua startup/cleanup](https://github.com/wireshark/wireshark/blob/v4.6.8/epan/wslua/init_wslua.c).
