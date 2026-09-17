# ProxyWin 0.5.0 verification — 2026-09-17

## Scope

- Fix the process-search caret jumping to the beginning after typing `w`.
- English menus, status, validation, event messages and application dialog buttons; concise labels with round `!` help buttons. User-saved names remain unchanged.
- Destination `*` for both IPv4 and IPv6, including process-wide DIRECT/PROXY/BLOCK rules. Ports and protocols still restrict matching; first-match ordering remains in effect.
- An unconditional earlier DIRECT rule does not require process attribution solely because a later rule filters by process.
- Preserve configuration version 2 and the existing application icon.

## Evidence

Windows 11 x64 10.0.26200; .NET SDK 10.0.103; official hash-pinned WinDivert 2.2.2 x64. `rtk proxy` was used for supported commands. The initial public source release is version 0.5.0, tagged `v0.5.0` in [pshho/ProxyWin](https://github.com/pshho/ProxyWin).

| Check | Result |
| --- | --- |
| Build and publication | Windows x64 self-contained publication succeeded; latest test build had zero warnings/errors |
| Original bug reproduction | Failed as expected: real WPF text composition inserted `w` with caret **0**, expected **1**; `artifacts/picker-before-v05.txt` |
| Fixed process picker | Passed: typing `w`, subsequent characters, middle insertion, selection replacement, Backspace, clear, and a manually entered non-running executable name; [report](docs/verification/v0.5.0-picker.txt) |
| Non-elevated regression groups | **16/16 passed**, [report](docs/verification/v0.5.0-unit.txt) |
| Wildcard matching | IPv4/IPv6, TCP/UDP, process-name restriction, order, IPv4-only `/0`, destination/port persistence passed |
| Native filter helper | Compiles/evaluates wildcard filters for both IP families and rejects nonmatching ports without opening a driver |
| Existing local behavior | SOCKS5 TCP/UDP, HTTP CONNECT, 32MiB local relay, rule actions, packet transforms, profile compatibility and encrypted roundtrip passed |
| English GUI | Compact/minimum layouts and editors rendered; DIRECT/PROXY/BLOCK and process-wide wildcard quick-add, observation-to-rule and process filtering passed; [report](docs/verification/v0.5.0-gui.txt), [screenshot](docs/images/main.png) |
| Published application | Caret and GUI smoke suites passed against the published DLL; published Core/Windows libraries match the rebuilt test libraries by SHA-256 |
| Administrator driver suite | **Not run: Windows UAC approval was cancelled.** `Start-Process -Verb RunAs` failed before the elevated apphost started; [status](docs/verification/v0.5.0-driver.txt) |

The caret regression was reproduced before the fix. WPF raises TextChanged before completing caret movement; synchronous item-list replacement restored the old selection. Filtering now runs after the edit completes and restores the current text/selection after dropdown updates. This is verified through WPF text composition, not just assigning the Text property.

The main implementing agent reviewed the changed-file list and diff, first-match routing and process attribution, wildcard native filters, profile compatibility, English messages and process-picker event ordering. This was not an independent review.

## Commands

```text
dotnet build src/ProxyWin.App/ProxyWin.App.csproj -c Release
dotnet run --project tests/ProxyWin.Tests/ProxyWin.Tests.csproj -c Release -- --report <artifacts/unit-test-v05.txt>
dotnet <ProxyWin.dll> --picker-test <artifacts/picker-after-v05.txt>
dotnet <ProxyWin.dll> --smoke-test <artifacts/ui-smoke-v05>
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-Driver.ps1
dotnet publish src/ProxyWin.App/ProxyWin.App.csproj -c Release -r win-x64 --self-contained true -o artifacts/ProxyWin-0.5.0-win-x64
```

GUI fixtures do not open a driver or change the user profile. PowerShell policy exceptions are process-local. The only observed expected test failure was the pre-fix caret reproduction; administrator verification remains incomplete because elevation was cancelled.

## Driver verification still required

The previous version's driver results do not establish version 0.5 wildcard behavior. The prepared administrator suite has 20 groups: 16 local groups plus four driver groups. The new group checks process-specific wildcard TCP/UDP PROXY, BLOCK and nonmatching-process passthrough. It runs through the uniquely named `ProxyWin.Tests.exe` apphost and selects port 7446. The engine also captures fragments because they cannot be reliably port-filtered.

Test traffic uses only `203.0.113.10` / `203.0.113.11` at declared ports and local fake proxy peers. A lower-priority test sink consumes DIRECT-test traffic. Observer fixtures restrict collection to test PIDs. There are no system routing changes, and a 60-second watchdog is retained.

## Limits

- Destination `*` means both IP families; `0.0.0.0/0` and `::/0` restrict the family. Partial IP patterns and domains are unsupported; use CIDR for ranges. Loopback/self destinations remain excluded.
- A process name matches all instances of that executable name, not one PID, path or signature. A blank process field means all processes. Broad destination rules capture more traffic before process attribution and can cost more CPU.
- BLOCK silently drops outbound packets; clients may time out. Stopping/exiting releases the filter. This is not an inbound firewall or a persistent kill switch.
- PROXY applies to new TCP connections. HTTP proxies remain TCP-only; UDP requires SOCKS5 UDP ASSOCIATE. Loop-prevention bypasses remain enabled for own relay sockets and active local proxy processes.
- IP fragment reassembly and SOCKS5 UDP fragmentation remain unsupported. Captured TCP/UDP fragments are dropped, including fragments that cannot yet be classified by process/port.
- Connection observation records new-flow metadata, not payloads. Existing flows and failed TCP attempts may be absent.
- Burp/TLS integration, long-duration load, abrupt process death, VPN coexistence, sleep/resume and live external IPv6 interception are not established by this verification. No throughput or reliability guarantee is made.
- Windows UAC and other OS-owned dialogs retain the Windows display language. The application does not change OS language settings.

The user profile at `%LOCALAPPDATA%/ProxyWin/profile.dat` is preserved. Release-file cleanup never targets that path.
