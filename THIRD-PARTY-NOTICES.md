# Third-party components

ProxyWin 0.5 uses the unmodified WinDivert DLL and signed driver through their public API. It does not use sing-box or Wintun. Its P/routing application icon is an original vector drawing included in the source.

| Component | Version / source | License information |
| --- | --- | --- |
| WinDivert | [2.2.2](https://github.com/basil00/WinDivert/tree/v2.2.2), Copyright Basil (Reqrypt) | Upstream license is included at `driver/LICENSE`; LGPLv3 or the alternative upstream GPLv2 terms. |
| .NET / WPF runtime | Included when publishing self-contained | Runtime distribution includes its own license and third-party notices. |

WinDivert is downloaded from the official release and hash-pinned. Source and build instructions are available at the version tag. The TCP redirection architecture follows the documented WinDivert packet-reflection approach. Preserve component license files when redistributing. ProxyWin is not affiliated with Reqrypt or PortSwigger.
