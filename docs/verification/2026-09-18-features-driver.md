# Update notifications, domain destinations and real driver validation

Date: 2026-09-18 (Asia/Seoul). Windows 11 x64 build 26200; .NET SDK 10.0.103; Whale 4.39.410.14; official WinDivert 2.2.2 x64 with verified hashes and Authenticode signature.

## Delivered behavior

- Check the public GitHub latest-release API asynchronously at startup. Show a newer stable version and open its fixed official release page on click. Current-version and failed-check states offer a manual retry. Requests have a 10-second timeout, use no credentials, and are cancelled when the window closes. Installation remains manual.
- Resolve domains in both quick-add and the rule editor. Accept mixed IP/CIDR/domain lists and internationalized names, retain all supported IPv4/IPv6 answers, and remove duplicate networks. Validate the entire input before DNS requests, keep the UI responsive, and leave saved rules unchanged on failure or cancellation.
- Store resolved IP snapshots in the existing profile format. Addresses do not refresh automatically; re-enter the domain to refresh. Existing IP matching, loopback restrictions and routing semantics remain in force.
- Provide an opt-in elevated Whale integration suite with isolated settings/browser profiles, traffic fixtures, resource samples and read-only WinDivert handle tracking.

## Verification results

| Check | Observed result |
| --- | --- |
| Windows build and self-contained publication | Passed; final builds had zero warnings/errors |
| Local regression groups | 19/19 passed |
| Local groups plus actual Windows DNS / public GitHub API | 21/21 passed; `github.com` resolved and release 0.5.2 was returned; [report](2026-09-18-features.txt) |
| Elevated driver regression groups | 23/23 passed: process-specific wildcard rules, DIRECT/BLOCK, SOCKS5 TCP/UDP, HTTP CONNECT, concurrent flows, observer coexistence and restart; [report](2026-09-18-driver.txt) |
| Published WPF GUI | Passed quick-add/editor domain conversion with asynchronous injected DNS responses, notification/current-version states, existing rules, compact layout and process picker; [report](2026-09-18-gui.txt) |
| Published keyboard/caret test | Passed real WPF typing, selection, insertion and backspace |
| Release-version tests / publisher fixtures | Both suites passed; publisher tests use a fake repository/CLI and did not publish a release |
| Driver signature and binary hashes | Passed `Setup-Driver.ps1` |
| Real Whale Apply/Stop | 20 cycles per run passed, with verified payloads and zero GUI NETWORK handles after each Stop. The separate FLOW monitor stayed active until explicitly stopped |
| Sustained Whale traffic | 600.5 seconds, 286 verified 4 MiB transfers; final active-session receive counter 1,240 MiB, Dropped 0, Errors 0; [soak report](2026-09-18-whale-soak.txt) |
| Final published app lifecycle | Repeated the cycles and a 31.8-second soak on the final self-contained executable; [report](2026-09-18-whale-final.txt) |
| Normal X/WM_CLOSE during traffic | Final build exited and released both WinDivert handles in 89.6 ms |
| Forced process termination during traffic | Final build exited and released both handles in 60.7 ms |
| Recovery after either exit | New test-destination requests no longer reached the proxy; ordinary direct Whale transfers still succeeded |
| User configuration | Encrypted user-profile hash unchanged. The original ProxyWin process and ordinary Whale session were preserved |
| Test process cleanup | Corrected harness passed another 20 cycles, both exits and a 10.6-second run; external process audit found **zero** remaining fixture processes; [report](2026-09-18-whale-cleanup.txt) |

The 10-minute run preceded final DNS/UI-test refinements; the packet engine was the same. The final self-contained application was then tested separately, including both exits with browser promises confirmed still pending. The initial soak log's `exit+release_ms` field also included subsequent recovery checks and pending-request timeouts; use the final report's separately measured exit times above.

## Performance and resource observations

The same real headless Whale browser fetched a known 32 MiB byte pattern from the same local test peer. Three downloads were timed for each path, with cache disabled and every returned byte checked. The proxy path crossed WinDivert and ProxyWin's TCP relay via an HTTP CONNECT peer; the direct path used the loopback listener.

| Measurement | 10-minute run | Final published build |
| --- | --- | --- |
| Direct download median | 41.2 ms / 6,515 Mbit/s | 41.7 ms / 6,437 Mbit/s |
| Diverted download median | 320.1 ms / 839 Mbit/s | 355.5 ms / 755 Mbit/s |
| Apply observed median | 62.3 ms | 62.4 ms |
| Stop observed median | 61.9 ms | 67.4 ms |
| Stop observed range | 57.1–77.2 ms | 58.4–125.7 ms |

UI operation timings include automation dispatch and polling overhead (50 ms waits). Throughput is local payload throughput, not WAN performance or a guaranteed minimum. The sustained workload used one 4 MiB request followed by a 2-second pause, and exit tests used eight simultaneous 32 MiB requests. Builds and other verification ran concurrently on this workstation, so these measurements are observations rather than a controlled comparative benchmark.

Across the 10-minute samples, ProxyWin private memory started at 70.9 MiB and ended at 70.0 MiB (range 65.8–78.9 MiB); handles decreased from 710 to 692 and threads from 29 to 18. Working set rose from 160.0 to 168.0 MiB. No sustained growth of private memory/handles or routing errors was observed in this interval; this does not establish indefinite leak-free operation.

## Capture shutdown versus driver service lifetime

Read-only REFLECT OPEN/CLOSE events established that the tested GUI owned zero NETWORK and FLOW handles after closing or termination. Recovery checks also established that no orphan relay handled new fixture requests.

**The Windows `WinDivert` kernel-driver service was still `Running` after both test runs.** Releasing an application's capture handles does not establish that the shared kernel module was unloaded. The application/test suite does not stop or delete that shared service. This behavior and the explicit uninstall procedure are described in the [official WinDivert documentation](https://reqrypt.org/windivert-doc.html#uninstalling). Therefore, these tests establish capture/relay cleanup, not automatic service unloading.

## Encountered failures and corrections

- Initial live `example.com` resolution timed out. The native Windows `Resolve-DnsName example.com -DnsOnly -QuickTimeout` command independently returned `ERROR_TIMEOUT`, while `github.com` resolved. The application reported its 10-second DNS timeout; the subsequent live feature suite used the reachable domain and passed. No DNS/system proxy settings were changed.
- The first additional GUI fixture used `localhost`, which correctly hit the existing loopback-destination prohibition. The fixture was changed to asynchronous injected documentation-address answers so hosted GUI checks remain deterministic and offline. The loopback safeguard was preserved; the subsequent published GUI suite passed.
- The initial live-test project build required correction of WPF namespace imports and redundant framework references. The final build passed without warnings or errors.
- The cleanup audit found that Whale's launcher can exit before its real browser process. The original test harness left 16 fixture-only browser processes across two runs. Those processes were explicitly identified by their isolated test profile paths and removed. The harness now obtains the actual browser PID from its dedicated DevTools endpoint for watchdog/cleanup ownership. The follow-up run passed, and an external process audit found zero remaining fixture processes without performing any additional termination. Existing user browser processes were not targeted.
- The first optional Windows event export produced no file when there were no matching events. The export now records an explicit empty array. A separate query for System critical/error events during 11:19–11:32 returned an empty array.

## Reproduction and boundaries

```powershell
dotnet build src/ProxyWin.App/ProxyWin.App.csproj -c Release
dotnet build tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release
dotnet build tests/ProxyWin.LiveTests/ProxyWin.LiveTests.csproj -c Release
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release -- --network-features
./scripts/Test-Whale.ps1 -SoakSeconds 600
# To validate a published executable:
./scripts/Test-Whale.ps1 -SoakSeconds 30 -AppPath '<publish-folder>/ProxyWin.exe'
dotnet '<publish-folder>/ProxyWin.dll' --smoke-test '<output-directory>'
dotnet '<publish-folder>/ProxyWin.dll' --picker-test '<report-file>'
```

Whale tests target only `203.0.113.10:18080/TCP` with a `whale.exe` rule, a local HTTP peer and a lower-priority sink preventing documentation-address traffic from leaving the host. Monitoring uses the actual GUI; reports retain counters and fixture data, not unrelated connection endpoints or payloads. System routes and the normal user profile are preserved. The explicit `--driver-fixture` application switch selects isolated settings for this harness.

Whale QUIC was disabled in this controlled TCP test. UDP was verified through the separate actual-driver SOCKS5 regression fixtures, not through a live Whale QUIC session. External websites/TLS interception, long-running high saturation, multiday operation, sleep/resume, VPN coexistence, network changes and external IPv6 interception remain unverified.

The main implementing agent performed a separate evidence/diff review covering async cancellation, profile persistence, fixed update URLs, rule bounds, process ownership and handle cleanup. This was not an independent review.
