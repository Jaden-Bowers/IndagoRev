# Network API evidence: first implementation

The bundled Frida `network` recipe now observes socket creation/acceptance,
bind/listen/connect, send/receive, shutdown and close APIs where exported. It
retains call IDs, native arguments/returns, bounded buffers and native sockaddr
bytes. This extends the existing backend; it is not another protocol decoder.

```text
indago runtime instrument --project demo --file TRUSTED_FIXTURE --backend frida --recipe network --max-events 512 --timeout-ms 3000
indago runtime observations --project demo --session RUN --kind api_enter
indago runtime observations --project demo --session RUN --kind api_leave
indago runtime identities --project demo --session RUN --kind socket
indago runtime network --project demo --session RUN --from 0 --limit 32
indago runtime identities --project demo --session RUN --kind api_call --id CALL_ID
```

Runtime launch/instrument still executes on the host, without a sandbox. Only
source-backed benign fixtures may run here. Unknown malware/challenges require
the future provider-attested disposable lab; WSL is not that boundary. Do not use
sample-derived remote destinations or capture unrelated host traffic.

## Identity and outcome contract

Each observed socket creation/acceptance assigns a fresh collection-local token,
even when an OS handle is reused. The collector prefixes it with the runtime
session and retains process/address-space IDs. Unknown preexisting handles are
only `candidate_handle_only`: seeing a numeric argument to a socket API does not
prove it names a valid socket. Negative/invalid descriptors do not create entries.
Creation success has `creation_observed: true`, but `identity_complete` remains
false: duplicate descriptors, inheritance, missed hooks and cross-process lifetime
resolution are not covered. These are not globally joined network-flow IDs.

Close observations retain their API outcome. A close racing an observed handle
replacement marks `socket_generation_race`; it does not delete the replacement or
close a lifetime with unsupported certainty. `runtime identities --kind socket`
filters the existing lifetime index. `--kind lifetime` still returns all observed
lifetime categories. Collection-end observation boundaries are not proof of OS
socket destruction.

Connect success means the API returned success, not proof of a TCP handshake or
remote behavior. Nonzero returns remain `failed_or_pending`. Windows Frida
`lastError` is not treated as the Winsock error code: Winsock requires
`WSAGetLastError`, which this recipe does not invoke. Zero-extended 32-bit Winsock
error returns are decoded as signed `int`, not huge successful byte counts.
[Microsoft connect contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect),
[Frida callback error fields](https://frida.re/docs/javascript-api/).

Send/receive retain the returned count separately from the attempted buffer;
`delivery_proven` is false. A zero count is not universally labeled a disconnect.
WSASend/WSARecv remain native leads with explicit unmodeled scatter/gather and
overlapped completion; they are not incorrectly counted as completed transfers.
No plaintext/TLS recovery guarantee is made.

## Bounds and gaps

New Frida collections also index API invocation tokens in the existing lifetime
store. `runtime identities --kind api_call --id CALL_ID` returns explicit entry
and return observation pointers, pairing status, duplicate/conflicting-event
flags and process/thread metadata. Fetch those source observations for their hashes
and native fields. `pair_complete` means the entry/return tokens paired without
detected conflict—not that a network operation succeeded or delivered bytes.
Collection closure does not invent a missing return. Older collections are not
retroactively backfilled by a read operation. Identity filtering by `--id` also
applies to sockets, epochs and other lifetime kinds.

For large or live sessions, start `runtime network --from 0 --limit 32` and pass
the returned `next_from` as `--from` and `snapshot_to` as `--to` for subsequent
pages. This seeks the existing session/sequence index and examines at most 256
source observations per call. An empty event page can still have a continuation
cursor when the window contained unrelated observations. Keep paging until the
cursor is null; start a new window after the previous snapshot to see later events.
This stabilizes the upper sequence bound, not the content of a concurrently edited
database; each inspected source record still has its hash checked.

Sources larger than 64 KiB are not loaded in cursor mode. Their pointers and
omission counts are reported (at most eight detailed pointers), with
`page_complete:false`; their network relevance is unknown. Source-row reads are
therefore at most 16 MiB, while rendered event bodies stay within 60,000 bytes.
The original filtered `--offset` mode remains for small sessions (offset capped at
10,000); it does not offer the sequence mode's fixed source-scan bound.

At most 1,024 handle entries are tracked within a collection. State exhaustion
produces unqualified identities and a partial collector result, not reused tokens.
Payload windows are at most 64 bytes, never more than the supplied receive buffer;
sockaddr windows are at most 128 bytes. Truncation/read failures remain explicit.
Accept/recvfrom return-address windows additionally respect the capacity read at
API entry, even if the returned address length grows. Unavailable or negative
Windows capacities do not permit a read. Capacity, returned length and read status
remain native evidence fields. Offline callback checks cover this refinement;
its rebuilt native worker checks passed on both platforms. The Linux check first
exposed a stale embedded-payload dependency, repaired and regression-tested as
described in [build-churn checks](build-churn.md).
The sockaddr representation is raw native ABI bytes, not normalized endpoints or
packet offsets. Event/duration limits and missing-return windows remain visible.

The following are still absent: offline PCAP/PCAPNG dissection, native Wireshark/
TShark packaging, packet/API joins, connection-incarnation identities, loss-aware
stream reassembly, async completion correlation and isolated capture/replay.
The intended packet path reuses native Wireshark dissection rather than inventing
another protocol stack; TShark supports offline files and structured output.
[TShark reference](https://www.wireshark.org/docs/man-pages/tshark.html).

## Verification status

Offline `tests/frida_network_recipe_tests.cjs` passed for mocked Windows/Linux
callbacks: creation, reuse, close races, invalid descriptors, pending/error
semantics, signed Winsock returns, byte/state limits and collection caps. Node is
a development-test tool only, not an application runtime dependency.

The Windows embedded-Frida smoke including bounded `runtime network` offset and
sequence paging and socket filtering passed in 6.12 seconds under a 60-second
storage watchdog (`out/qualification-frida-65202a6fdb0e4045b89ba10bcbc81e06/`). Its
fixture creates/closes unconnected sockets and calls connect with an invalid
descriptor; it sends no packets. Linux API/offset/filter smoke passed under a
60-second watchdog (`out/network-linux-frida-checks.log`). The later Linux native
checks passed 5/5, including the sparse/oversized/corrupt cursor fixture
(`out/network-cursor-linux-checks.log`); embedded Frida sequence paging passed
under a 60-second watchdog (`out/network-cursor-linux-frida-checks.log`). Windows
native checks passed 4/4 in 7.99 seconds (`out/network-cursor-windows-checks.log`).
These are bounded development checks, not production
qualification or complete network-debugging validation.

The later capacity/call-pairing Windows native checks passed 4/4 in 9.12 seconds
and the embedded Frida smoke passed in 6.76 seconds. Linux native checks passed
5/5 (`out/frida-pairing-linux-checks.log`), and the repaired embedded worker passed
`out/payload-dependency-linux-frida-checks.log` under a 60-second watchdog. These
checks resolve indexed API call pairs back to their source observations.
