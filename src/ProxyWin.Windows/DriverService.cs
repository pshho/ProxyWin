using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ProxyWin.Windows;

public sealed record DriverUnloadResult(bool Unloaded, string Message);

public static class DriverService
{
    // Serializes our native opens against idle checks / service stop in this process.
    internal static readonly object SyncRoot = new();
    public static Task<DriverUnloadResult> TryUnloadAsync() => Task.Run(TryUnload);
    private static DriverUnloadResult TryUnload()
    {
        lock (SyncRoot)
        {
            try
            {
                // Same installation mutex as the official WinDivert library / utility.
                using var mutex = new Mutex(false, "WinDivertDriverInstallMutex");
                var acquired = false;
                try
                {
                    try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(3)); }
                    catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) return new(false, "WinDivert retained: driver installation is busy.");
                    using var manager = OpenSCManager(null, null, 1);
                    if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    using var service = OpenService(manager, "WinDivert", 4 | 32);
                    if (service.IsInvalid)
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error == 1060) return new(true, "WinDivert is not loaded.");
                        throw new Win32Exception(error);
                    }
                    var status = Status(service);
                    if (status.State == 1) return new(true, "WinDivert is stopped.");
                    if (status.Type != 1 || status.State != 4) return new(false, "WinDivert retained: service is changing state.");
                    // Never stop a different driver that happens to use the same service name.
                    using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDivert");
                    var path = (key?.GetValue("ImagePath") as string ?? "").Trim('"');
                    if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
                    if (!Path.IsPathFullyQualified(path) || !Path.GetFileName(path).Equals("WinDivert64.sys", StringComparison.OrdinalIgnoreCase))
                        return new(false, "WinDivert retained: unrecognized driver service path.");
                    using (var file = File.OpenRead(path))
                        if (!Convert.ToHexString(SHA256.HashData(file)).Equals(WinDivertNative.DriverHash, StringComparison.OrdinalIgnoreCase))
                            return new(false, "WinDivert retained: another driver version is installed.");
                    if (WinDivertNative.HasActiveHandles())
                        return new(false, "WinDivert retained: capture or monitoring is still in use.");
                    // Inspection handles must be closed before asking Windows to unload.
                    // Windows may still refuse if another client opens during this interval.
                    if (!ControlService(service, 1, out status))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (error != 1062) throw new Win32Exception(error);
                    }
                    var deadline = Environment.TickCount64 + 3000;
                    while ((status = Status(service)).State != 1 && Environment.TickCount64 < deadline) Thread.Sleep(50);
                    return status.State == 1 ? new(true, "WinDivert unloaded.") : new(false, "WinDivert stop is pending; another handle may still be open.");
                }
                finally { if (acquired) mutex.ReleaseMutex(); }
            }
            catch (Win32Exception ex) { return new(false, $"WinDivert unload unavailable: Windows error {ex.NativeErrorCode}. Driver left installed."); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { return new(false, $"WinDivert retained: {ex.GetType().Name} while verifying the service."); }
        }
    }

    private static ServiceStatus Status(ServiceHandle service)
    {
        if (!QueryServiceStatus(service, out var status)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return status;
    }
    public static bool IsStopped()
    {
        using var manager = OpenSCManager(null, null, 1);
        if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        using var service = OpenService(manager, "WinDivert", 4);
        if (!service.IsInvalid) return Status(service).State == 1;
        var error = Marshal.GetLastWin32Error();
        if (error == 1060) return true;
        throw new Win32Exception(error);
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    { public uint Type, State, Controls, Win32ExitCode, ServiceExitCode, Checkpoint, WaitHint; }
    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatus(ServiceHandle service, out ServiceStatus status);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
}
