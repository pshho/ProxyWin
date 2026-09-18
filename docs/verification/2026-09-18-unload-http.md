# Idle driver unloading and HTTP relay diagnostics

## Changes

ProxyWin now attempts to unload the pinned WinDivert driver after Stop, Stop monitor or window close when routing and monitoring are both inactive. It uses the official installation mutex, verifies the configured driver's filename and SHA-256, obtains a read-only REFLECT snapshot without installing a driver, closes that snapshot, and asks Windows to stop the service. Other active capture/monitor users, another installed driver version, access errors and stop timeouts cause a retained/deferred result rather than terminating another application.

A hidden cleanup process is armed before the GUI opens its first driver handle. It identifies the parent by PID and start time, keeps no WinDivert handle while waiting, and performs the same cleanup after the exact parent exits. It then writes a status-only `driver-cleanup.txt` beside the selected profile and exits. This covers termination of the GUI alone; it does not promise cleanup if the guard is also terminated, the machine loses power, or Windows refuses to unload. Shared-driver idle detection is a snapshot, not an atomic reservation against uncooperative external programs opening new handles concurrently.

The service-stop approach follows the [official WinDivert 2.2.2 control utility](https://github.com/basil00/WinDivert/blob/v2.2.2/examples/windivertctl/windivertctl.c). Driver files, system routes, proxy credentials and saved routing rules are not changed by unloading. Apply or Start monitor loads the driver again through the normal WinDivert API.

HTTP CONNECT failures now retain their numeric status and distinguish handshake failures, socket error codes and local socket-owner lookup failures. The logger never prints arbitrary exception text, response reason phrases, headers, bodies or credentials. Existing local-proxy loop protection and failure behavior are preserved.

## Evidence on Windows 11 / WinDivert 2.2.2

| Check | Result |
| --- | --- |
| Existing diagnostic defect | Reproduced with a local HTTP peer: HTTP 403 was replaced with `HTTP CONNECT rejected. Check the proxy and credentials.` |
| HTTP diagnostics / local regressions | **20/20 passed**; actual 403/407/502 replies retain status without test secrets; nested ConnectionReset and local-owner failures are distinguished |
| Elevated driver regressions | **24/24 passed** after the unload/HTTP changes |
| Published application GUI | Existing published WPF smoke suite passed |
| Other active WinDivert capture | Unload was declined and the existing engine/service stayed running |
| Idle shared service | Stopped/unloaded and confirmed `STOPPED` or absent via Windows service status |
| Apply / Stop unload-reload | Six cycles per unload-suite run passed |
| Monitor active after routing Stop | Driver remained loaded; stopping the last monitor unloaded it |
| Published GUI normal close | Service stopped/absent and guard completed in **120.8 ms** in the later run |
| Published GUI forced termination | Guard unloaded the service in **58.4 ms** in the later run |
| Whale traffic regression | 20 Apply/Stop cycles, a 31.6-second run with 15 byte-verified 4 MiB downloads, X/forced exit and direct recovery passed; Dropped 0 / Errors 0 |
| Shared use across processes | The Whale harness's external sink remained open, so the GUI/guard reported `WinDivert retained: capture or monitoring is still in use.` instead of stopping it |
| Build | Final application and integration harness compiled without warnings/errors |
| Extra close-during-start case | **Pending**: see the failed fixture and cancelled UAC rerun below |

Reports:

- [Local diagnostics/regression report](2026-09-18-unload-unit.txt)
- [Initial complete unload suite](2026-09-18-unload-initial.txt)
- [Later unload run, including the extra fixture failure](2026-09-18-unload-extra.txt)
- [Driver regression report](2026-09-18-unload-driver.txt)
- [Whale regression report](2026-09-18-unload-whale.txt)

The later run passed the six unload/reload cycles, monitor retention and both exit paths. Its added immediate-close fixture timed out waiting for a guard report. UI Automation's Invoke queues the click, so the old fixture could close the window before Apply dispatched; in that case no guard was needed or started. The fixture now waits for the Working/Active state before closing, retains its strict service-stop/report checks, and compiles successfully. **Windows UAC was cancelled when starting that corrected rerun, so it was not executed.** The product code also checks `closing` after guard startup to prevent a late engine/monitor reopen and waits for guard startup during normal close; that additional race path is reviewed but runtime verification remains pending.

An initial build also caught a nullable executable-path dereference in the guard; this was corrected by explicitly rejecting an unavailable executable path. The original HTTP-status assertion failed before the diagnostic fix and passed afterward. No tests or loop-prevention checks were disabled to obtain passing results.

## Scope of the other-PC Burp diagnosis

The reported facts are: another PC, Burp Suite, HTTP proxy at `127.0.0.1`, and errors while browsing after Apply. HTTP is the correct protocol selection for a normal Burp listener. The old generic IOException message is insufficient to determine that PC's underlying failure; it could hide CONNECT rejection, a reset/closed TCP stream, or a failed Windows socket-owner lookup. **No claim is made that the other PC's connection failure was reproduced or fixed.**

For HTTPS, check that the browser on that PC trusts the CA of that Burp installation. Burp generates a unique CA per installation; an earlier PC's trust setup does not establish trust for this one. This is a candidate to investigate, not a confirmed diagnosis. See [PortSwigger's CA documentation](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate).

Compare the new ProxyWin Events entry with Burp's Dashboard Event log at the same time. TLS negotiation/certificate errors, a CONNECT status, and a socket reset indicate different paths. PortSwigger also recommends the [Event log for connection troubleshooting](https://portswigger.net/burp/documentation/desktop/troubleshooting/troubleshooting). ProxyWin sends CONNECT to a numeric destination; browser-configured proxying commonly supplies a hostname instead. ProxyWin does not rewrite TLS SNI or bypass certificate validation.

## Reproduction

```powershell
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release
dotnet build src/ProxyWin.App/ProxyWin.App.csproj -c Release
dotnet build tests/ProxyWin.LiveTests/ProxyWin.LiveTests.csproj -c Release
./scripts/Test-Whale.ps1 -SoakSeconds 30 -AppPath '<published ProxyWin.exe>'
./scripts/Test-Unload.ps1 -AppPath '<published ProxyWin.exe>'
```

Run the unload suite when other WinDivert users are idle; it refuses to begin if a different capture is active. The main implementing agent separately reviewed driver identity checks, handle disposal, shared users, start/close ordering, parent identity and diagnostic redaction. This is not an independent review.
