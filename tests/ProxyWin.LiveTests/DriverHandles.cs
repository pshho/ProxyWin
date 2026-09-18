using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;

// Read-only REFLECT events establish whether a particular GUI PID released its handles.
internal sealed class DriverHandles : IDisposable
{
    private readonly IntPtr handle;
    private readonly Task reader;
    private readonly ConcurrentDictionary<(uint Pid, long Opened), int> active = new();
    private volatile bool stopping;
    public Exception? Error { get; private set; }
    public DriverHandles()
    {
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "driver", "WinDivert.dll"));
        handle = WinDivertOpen("true", 4, 0, 1 | 4);
        if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        reader = Task.Factory.StartNew(Read, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
    public int Count(int pid, int? layer = null) => active.Count(p => p.Key.Pid == pid && (layer is null || p.Value == layer));
    private void Read()
    {
        var packet = new byte[65575];
        while (WinDivertRecv(handle, packet, (uint)packet.Length, out _, out var address))
        {
            var key = (address.ProcessId, address.Opened);
            if (((address.Flags >> 8) & 255) == 8) active[key] = address.Layer;
            if (((address.Flags >> 8) & 255) == 9) active.TryRemove(key, out _);
        }
        if (!stopping) Error = new Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Dispose()
    {
        stopping = true; WinDivertShutdown(handle, 1);
        if (!reader.Wait(TimeSpan.FromSeconds(5))) { WinDivertClose(handle); throw new TimeoutException("REFLECT reader did not stop."); }
        WinDivertClose(handle);
    }
    public static IDisposable TestSink()
    {
        var sink = WinDivertOpen("outbound and ip.DstAddr == 203.0.113.10 and tcp.DstPort == 18080", 0, -100, 0);
        if (sink == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new Sink(sink);
    }
    private sealed class Sink(IntPtr value) : IDisposable { public void Dispose() => WinDivertClose(value); }
    [StructLayout(LayoutKind.Explicit, Size = 80)]
    private struct Address
    {
        [FieldOffset(8)] public uint Flags;
        [FieldOffset(16)] public long Opened;
        [FieldOffset(24)] public uint ProcessId;
        [FieldOffset(28)] public int Layer;
    }
    [DllImport("WinDivert.dll", SetLastError = true, CharSet = CharSet.Ansi)] private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint length, out uint received, out Address address);
    [DllImport("WinDivert.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WinDivertShutdown(IntPtr handle, int how);
    [DllImport("WinDivert.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WinDivertClose(IntPtr handle);
}
