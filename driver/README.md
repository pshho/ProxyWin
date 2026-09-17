# WinDivert 2.2.2, x64

`scripts/Setup-Driver.ps1` downloads the unmodified official signed build, checks pinned SHA-256 values and checks the SYS Authenticode signature. Runtime also checks DLL/SYS hashes before opening capture. Driver files stay beside one another in the app's `driver` directory.

- Source/release: https://github.com/basil00/WinDivert/releases/tag/v2.2.2
- Archive: `WinDivert-2.2.2-A.zip`
- Archive SHA-256: `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`
- DLL SHA-256: `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2`
- SYS SHA-256: `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2`

Opening the driver requires Administrator privileges. Closing the handle removes this app's filters; the shared WinDivert driver service itself may remain loaded. The app does not uninstall a driver another application may be using.
