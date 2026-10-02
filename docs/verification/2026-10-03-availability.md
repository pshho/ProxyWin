# Availability regression verification — 2026-10-03

Windows x64 10.0.26300, .NET SDK 10.0.103 / runtime 10.0.3, pinned WinDivert 2.2.2. Baseline source: `e48e959`. The original non-elevated suite passed 21/21 groups; the new regressions exposed additional failures before the fixes.

## Reproduced problems and fixes

| Problem reproduced before the fix | Corrected behavior and evidence |
| --- | --- |
| Closing a window without active driver sessions called `Close()` recursively from `Closing`, raising a WPF `InvalidOperationException`. | Cleanup yields to the dispatcher before the final close. The GUI fixture waits for `Closed`, checks the process exit code, and retains dispatcher failures instead of overwriting them with PASS. |
| A real file-sharing violation left a rule checkbox changed although saving failed. Enabling an existing observed rule could also log success after a failed save. | The checkbox returns to the saved state; the failed observed-rule edit returns without a success message. The test verifies the encrypted file is unchanged, temporary files are removed, and editing recovers after unlocking. |
| HTTP CONNECT rejected a successful 201 reply and a 100 interim reply. A complete response ending at exactly the 16 KiB bound was also rejected. | All successful 2xx replies establish the tunnel; interim replies are consumed before the final response. Cases cover 200/201/204/299 and 100/103. The shared 16 KiB budget and 10-second timeout remain bounded. Tests also verify that coalesced binary tunnel bytes are preserved. See [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6). |
| Local proxy ownership was inferred from port alone, including unrelated listeners at other addresses. Loopback aliases such as `127.0.0.2` were not recognized as local. | Match address, address family and port, including matching wildcard listeners and loopback aliases. Deterministic row fixtures and real Windows IPv4, IPv6 and dual-mode listeners pass. Fresh owner lookup is retained; no stale PID cache was introduced. |
| A relative `ProfileStore` path changed meaning after the process working directory changed. | Resolve the directory once at construction. Load and subsequent save keep using the original directory. |
| `Network.Contains` allocated three address arrays on successful CIDR comparisons. | Stack-backed address comparison preserves IPv4/IPv6 boundaries. The same warmed test measured **4,320,000 allocated bytes before and 0 after, for 40,000 calls**. This measures this method only; it is not a whole-application throughput claim. |

## Completed checks

| Check | Result |
| --- | --- |
| Local regression groups | **32/32**, [full report](2026-10-03-unit.txt). |
| Concurrent TCP relays | 128 relays in four waves of 32; 16 MiB verified in each direction; byte counters, half-close/EOF and socket registration cleanup checked. |
| Handshake cancellation | 16 SOCKS5 and 16 HTTP cancellation cycles; registrations released. |
| UDP cancellation and bounds | 32 cancellation cycles, each filling the 32-packet queue; overload rejected and the complete 16 MiB shared budget recovered after each cycle. |
| TCP mapping capacity | All 16,384 slots, unique virtual ports, listener-port exclusion, overflow rejection and expiry recovery checked. |
| Existing transfer regression | 32 MiB byte-checked relay with half-close, both directly and through the driver suite. Local measurements are not WAN guarantees. |
| Published WPF GUI and saved-state failure paths | PASS, exit 0; [report](2026-10-03-gui.txt). Isolated encrypted profile; no user profile changed. |
| Published keyboard/caret fixture | PASS, exit 0; [report](2026-10-03-picker.txt). |
| Real Windows DNS and public GitHub API | **34/34** groups including the local suite and two external integration checks; [report](2026-10-03-network.txt). |
| Administrator driver suite | **37/37**, including TCP/UDP interception, wildcard/process rules, observation, update-socket bypass, concurrent traffic and restart; [report](2026-10-03-driver.txt). |
| Release scripts | Version selection/boundaries passed; all eight mocked publisher success/failure/retry scenarios passed without publishing. |
| Build and local packaging | Driver hashes/signature verified; self-contained Windows x64 publication and ZIP/checksum creation succeeded. |
| Whale 600-second soak and exit checks | PASS: 601.9 seconds, 286 soak transfers, 20 Apply/Stop cycles, no reported drops/errors, normal and forced exit during traffic; [report](2026-10-03-whale.txt). |
| Exclusive idle-driver unload/reload | PASS: six Apply/Stop reload cycles, monitor retention, active-client preservation, normal/forced exit, close during Apply; final service STOPPED/absent; [report](2026-10-03-unload.txt). |

The soak recorded 20 process samples: private memory ranged from **130.95 to 139.10 MiB** and ended at **137.11 MiB**; handles ranged from **1,214 to 1,241**, ending at **1,219**. There was no sustained upward handle trend in these samples; this duration does not establish freedom from slow leaks. The GUI recorded 1,240 MiB downloaded across the benchmark/soak phase, with zero reported blocked/dropped/error counts. Closing during traffic released all GUI WinDivert handles in 143.7 ms for normal close and 61.4 ms for forced termination in this run. The regular user profile was unchanged.

The System event collector recorded one `Volsnap` event ID 36 during the soak interval. It records provider/ID counts only; these tests do not establish a relationship between that OS event and ProxyWin. The successful traffic/exit assertions do not imply an error-free Windows System log.

## Commands

Run from the repository root on Windows; PowerShell execution-policy exceptions are process-local.

```powershell
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release -- --report artifacts/availability-after.txt
dotnet tests/ProxyWin.Tests/bin/Release/net10.0-windows/ProxyWin.Tests.dll --network-features --report artifacts/availability-network.txt
./scripts/Test-ReleaseVersion.ps1
./scripts/Test-PublishRelease.ps1
./scripts/Build.ps1
dotnet artifacts/ProxyWin-0.5.0-win-x64/ProxyWin.dll --smoke-test artifacts/availability-ui-final
dotnet artifacts/ProxyWin-0.5.0-win-x64/ProxyWin.dll --picker-test artifacts/availability-picker.txt
dotnet build tests/ProxyWin.LiveTests/ProxyWin.LiveTests.csproj -c Release
./scripts/Test-Whale.ps1 -SoakSeconds 600 -OutputDirectory artifacts/availability-whale -AppPath artifacts/ProxyWin-0.5.0-win-x64/ProxyWin.exe
./scripts/Test-Unload.ps1 -OutputDirectory artifacts/availability-unload -AppPath artifacts/ProxyWin-0.5.0-win-x64/ProxyWin.exe
```

Packaging was exercised with `./scripts/Package-Release.ps1 -Version 0.5.0` after copying this run's published GUI report to `artifacts/ci/gui/result.txt`. An initial invocation omitted its mandatory `Version` argument and failed before doing work; the corrected invocation passed. The local package uses the project's base version for testing and is not a newly published release.

## Review and limits

The main agent reviewed the complete diff and executed verification. A separate agent reviewed the HTTP CONNECT and UI save/close changes and found no additional concrete defect; delegated implementers reviewed their assigned Core and socket-owner areas. This is not an exhaustive audit.

The pre-fix test failures were observed, not inferred from static code alone. GUI tests also exposed a test-reporting defect: a PASS file could hide a dispatcher failure while the process returned 1. Both the report and exit status are now checked.

These checks do not prove absence of all availability problems. Multi-day operation, sleep/resume, VPN coexistence, arbitrary network/interface changes, real remote proxy vendors and public IPv6 interception remain unverified. Packet fragmentation handling remains the documented fail-closed limitation; no fragment reassembly or broad routing-policy change was made. Full Windows owner-table queries remain a possible cost under high process-specific UDP load; avoiding stale process attribution takes precedence over speculative caching.

## Release preparation follow-up

The initial delivery rerun passed 32/32 local groups. Subsequent [PR CI run 37034165291](https://github.com/pshho/ProxyWin/actions/runs/37034165291), using .NET SDK 10.0.401/runtime 10.0.12 on Windows Server 2025, failed 2 of 32 groups:

- The cancelled-handshake fixture received an `IOException` with inner Windows socket `OperationAborted (995)`, wrapped as a handshake error. `OpenAsync` now converts this specific error to `OperationCanceledException` only when its linked cancellation token is cancelled, disposes the connection, and preserves a cancelled token. Other I/O failures retain the original diagnostic path. The fixture also asserts that cancellation retains a cancelled token.
- The CIDR fixture measured 24,624 bytes despite zero allocation in the local run. Its separate warm-up and measurement loops allowed runtime/JIT warm-up to affect the measured path; JIT timing is a suspected explanation, not a captured allocation trace. The fixture now warms and measures the same non-inlined, eagerly optimized helper. The original 4,096-byte failure threshold and 40,000 measured calls are unchanged. Restoring the old allocating `Contains` implementation temporarily made the revised fixture fail at 4,320,000 bytes (31/32 groups); the production implementation was then restored.

After the cancellation and fixture corrections, the local suite passed 32/32 with zero measured CIDR allocation. The administrator, external-network, Whale and interactive caret results above predate this follow-up; they were not rerun for these release-preparation changes. Final hosted CI separately checks the corrected source and published GUI before release. The main agent performed this follow-up and diff review; it is not an independent review.
