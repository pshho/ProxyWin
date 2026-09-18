using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Net;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProxyWin.Windows;

[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct DivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint Flags;
    [FieldOffset(16)] public uint Interface;
    [FieldOffset(20)] public uint SubInterface;
    [FieldOffset(16)] public ulong FlowEndpoint;
    [FieldOffset(32)] public uint FlowProcessId;
    [FieldOffset(36)] public uint FlowLocal0;
    [FieldOffset(40)] public uint FlowLocal1;
    [FieldOffset(44)] public uint FlowLocal2;
    [FieldOffset(48)] public uint FlowLocal3;
    [FieldOffset(52)] public uint FlowRemote0;
    [FieldOffset(56)] public uint FlowRemote1;
    [FieldOffset(60)] public uint FlowRemote2;
    [FieldOffset(64)] public uint FlowRemote3;
    [FieldOffset(68)] public ushort FlowLocalPort;
    [FieldOffset(70)] public ushort FlowRemotePort;
    [FieldOffset(72)] public byte FlowProtocol;
    [FieldOffset(16)] public long ReflectOpened;
    [FieldOffset(24)] public uint ReflectProcessId;
    public void Inbound() => Flags &= ~(1u << 17);
}

internal sealed class DivertHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public DivertHandle() : base(true) { }
    protected override bool ReleaseHandle() => WinDivertNative.WinDivertClose(handle);
    public void Abort()
    {
        if (IsInvalid || IsClosed) return;
        WinDivertNative.WinDivertClose(DangerousGetHandle()); SetHandleAsInvalid();
    }
}

internal static class WinDivertNative
{
    internal const string DriverHash = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";
    public const int BatchSize = 64;
    public const int ShutdownReceive = 1;
    public const int BufferSize = 65575 * BatchSize;
    static WinDivertNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(WinDivertNative).Assembly, (name, _, _) => name == "WinDivert.dll"
            ? NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "driver", "WinDivert.dll")) : IntPtr.Zero);
    }

    public static void VerifyFiles()
    {
        foreach (var (name, hash) in new[]
        {
            ("WinDivert.dll", "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"),
            ("WinDivert64.sys", DriverHash)
        })
        {
            var path = Path.Combine(AppContext.BaseDirectory, "driver", name);
            if (!File.Exists(path)) throw new FileNotFoundException($"Missing driver/{name}. Keep the full release folder.");
            using var file = File.OpenRead(path);
            if (!Convert.ToHexString(SHA256.HashData(file)).Equals(hash, StringComparison.OrdinalIgnoreCase))
                throw new IOException($"Driver integrity check failed: {name}.");
        }
    }

    public static void ValidateFilter(string filter)
    {
        if (!WinDivertHelperCompileFilter(filter, 0, IntPtr.Zero, 0, out var error, out var position))
            throw new FormatException($"Invalid capture filter ({position}): {Marshal.PtrToStringAnsi(error)}");
    }
    internal static unsafe bool Evaluate(string filter, byte[] packet)
    {
        var address = new DivertAddress { Flags = (1u << 17) | ((packet[0] >> 4) == 6 ? 1u << 20 : 0) };
        fixed (byte* pointer = packet) return WinDivertHelperEvalFilter(filter, pointer, (uint)packet.Length, ref address);
    }
    public static DivertHandle Open(string filter, short priority = 100)
    {
        var handle = WinDivertOpen(filter, 0, priority, 0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error(); handle.Dispose();
            throw new Win32Exception(error, $"Cannot start WinDivert ({error}). Check administrator access and the driver.");
        }
        if (!WinDivertSetParam(handle, 0, 8192) || !WinDivertSetParam(handle, 1, 1000) || !WinDivertSetParam(handle, 2, 16 * 1024 * 1024))
        {
            var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error);
        }
        return handle;
    }

    internal static DivertHandle OpenFlow(int? onlyProcessId)
    {
        // FLOW is metadata-only. SNIFF | RECV_ONLY can neither divert nor inject traffic.
        var processFilter = onlyProcessId is { } pid ? $"processId == {pid}" : $"processId != {Environment.ProcessId}";
        var filter = $"outbound and event == ESTABLISHED and ({processFilter})";
        var handle = WinDivertOpen(filter, 2, 0, 0x0001 | 0x0004);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error(); handle.Dispose();
            throw new Win32Exception(error, $"Cannot start the monitor ({error}). Check administrator access and the driver.");
        }
        return handle;
    }

    internal static IPAddress FlowIp(uint a, uint b, uint c, uint d)
    {
        var text = new StringBuilder(64);
        if (!WinDivertHelperFormatIPv6Address([a, b, c, d], text, 64) || !IPAddress.TryParse(text.ToString(), out var address))
            throw new IOException("Cannot decode the connection address.");
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ReceiveFlow(DivertHandle handle, IntPtr packet, uint length, IntPtr received, out DivertAddress address);
    [DllImport("WinDivert.dll", CharSet = CharSet.Ansi)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertHelperFormatIPv6Address([In] uint[] address, StringBuilder text, uint length);

    internal static bool HasActiveHandles()
    {
        using var snapshot = WinDivertOpen("true", 4, 0, 1 | 4 | 16); // SNIFF | RECV_ONLY | NO_INSTALL
        if (snapshot.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            if (error == 1060) return false;
            throw new Win32Exception(error);
        }
        if (!WinDivertShutdown(snapshot, 3)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var active = new HashSet<(uint, long)>(); var buffer = new byte[65575];
        while (ReceiveReflect(snapshot, buffer, (uint)buffer.Length, out _, out var address))
        {
            var key = (address.ReflectProcessId, address.ReflectOpened);
            if (((address.Flags >> 8) & 255) == 8) active.Add(key);
            if (((address.Flags >> 8) & 255) == 9) active.Remove(key);
        }
        var receiveError = Marshal.GetLastWin32Error();
        if (receiveError != 232) throw new Win32Exception(receiveError);
        return active.Count != 0;
    }
    private static DivertHandle WinDivertOpen(string filter, int layer, short priority, ulong flags)
    {
        lock (DriverService.SyncRoot) return OpenNative(filter, layer, priority, flags);
    }
    [DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", CharSet = CharSet.Ansi, SetLastError = true)] private static extern DivertHandle OpenNative(string filter, int layer, short priority, ulong flags);
    [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReceiveReflect(DivertHandle handle, byte[] packet, uint length, out uint received, out DivertAddress address);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool WinDivertClose(IntPtr handle);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool WinDivertShutdown(DivertHandle handle, int how);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WinDivertSetParam(DivertHandle handle, int parameter, ulong value);
    [DllImport("WinDivert.dll", CharSet = CharSet.Ansi)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertHelperCompileFilter(string filter, int layer, IntPtr buffer, uint length, out IntPtr error, out uint position);
    [DllImport("WinDivert.dll", CharSet = CharSet.Ansi)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern unsafe bool WinDivertHelperEvalFilter(string filter, byte* packet, uint length, ref DivertAddress address);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool WinDivertRecvEx(DivertHandle handle, byte* packet, uint length, out uint received, ulong flags, [Out] DivertAddress[] addresses, ref uint addressLength, IntPtr overlapped);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool WinDivertSendEx(DivertHandle handle, byte* packet, uint length, out uint sent, ulong flags, [In] DivertAddress[] addresses, uint addressLength, IntPtr overlapped);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool WinDivertSend(DivertHandle handle, byte* packet, uint length, out uint sent, ref DivertAddress address);
    [DllImport("WinDivert.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool WinDivertHelperCalcChecksums(byte* packet, uint length, ref DivertAddress address, ulong flags);
}
