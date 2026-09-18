# Update checks while routing is Active

The reported behavior was a failed update check while rules were Active, with the same check working after Stop on another PC. This is not intended behavior. The old diagnostic also hid every cause behind “Rules are unchanged”.

## Cause and fix

The packet path excluded the current process only when socket-owner lookup happened to be needed for a process rule or a recognized local proxy. Broad rules without either condition could therefore process the application's own update TCP connection as ordinary traffic. A required owner lookup could also fail; ownership was not established explicitly for the updater.

The updater now uses an HttpClient connection callback that binds an exclusive TCP port, registers ownership **before the first SYN**, and retains the registration for the underlying stream's lifetime. The engine honors this registration before matching user rules. Registrations are independent of an engine session, so pooled update connections remain identified across Apply/Stop. Disposal, failed connection and cancellation release registrations. The existing socket-bypass generation guard prevents an older lease removing a newer registration.

The exemption identifies application-owned TCP sockets, not all GitHub IPs or other applications' connections. Windows/system proxy selection and TLS certificate verification use the normal .NET behavior; neither is disabled. DNS performed by Windows and other software's own proxy connections are still subject to their existing environment/policy.

The tooltip and Events now distinguish DNS, TLS, system-proxy, timeout and HTTP-status failures using fixed text and numeric status, without raw exception messages, response bodies or credentials.

## Verification

- **Before:** with the legacy packet decision restored, the controlled native regression failed: `managed updater TCP must not enter user BLOCK rules` (**21/22 groups passed**). This reproduces the missing exemption, not the unavailable other PC's exact Burp configuration.
- **After:** **26/26 groups passed**, including the native regression and the existing SOCKS5, HTTP CONNECT, UDP, observation, rule-order and restart tests. The driver was unloaded after the suite.
- Across two native Apply/Stop cycles, ordinary TCP connections remained blocked, the managed update connection reached the lower-priority sink unchanged, and ordinary TCP remained blocked after update connection cleanup.
- IPv4/IPv6 loopback transport, exclusive port reservation, TCP-versus-UDP scope, synchronous/asynchronous disposal, cancelled and refused connection cleanup passed.
- Actual Windows DNS and public GitHub HTTPS integration passed: **23/23 groups**, latest release `0.5.4` at test time.
- WPF build passed with zero warnings/errors. GUI smoke coverage includes safe update-failure details and Retry display, in addition to existing GUI checks.

Saved evidence: [driver regression report](2026-09-18-update-driver.txt), [live Windows network report](2026-09-18-update-network.txt).

The native fixture uses only `203.0.113.10:7447/TCP`, with a lower-priority sink preventing test traffic leaving the host. It observes packet decisions; it does not claim to perform a complete public HTTPS request through that synthetic endpoint. The separate live HTTPS check verifies the production HttpClient callback.

Commands:

```powershell
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release
./scripts/Test-Driver.ps1 -UpdateOnly -ReportPath '<before-report>'
./scripts/Test-Driver.ps1 -ReportPath '<after-report>'
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release -- --network-features
dotnet build src/ProxyWin.App/ProxyWin.App.csproj -c Release
dotnet src/ProxyWin.App/bin/Release/net10.0-windows/ProxyWin.dll --smoke-test '<GUI-output>'
```

An initial API-quota fixture exposed the old checker's lack of a fallback, but the user's Active-versus-Stopped clarification narrowed this fix to self-traffic interception. That API-fallback proposal was not included. The main agent reviewed ownership timing, stream lifetime, failure cleanup, rule preservation and diagnostic redaction in a separate pass; this was not an independent review. The other PC's exact configuration still needs confirmation with the fixed build if a failure persists.
