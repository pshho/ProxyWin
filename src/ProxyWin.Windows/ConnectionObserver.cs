using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public sealed class ConnectionObserver : IAsyncDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly ConcurrentQueue<ObservedConnection> pending = new();
    private ObservationSession? session;
    private long skipped;
    public bool IsRunning => session is { Running: true };
    public long Skipped => Interlocked.Read(ref skipped);
    public string? LastError { get; private set; }
    private sealed class ObservationSession(DivertHandle handle)
    {
        public DivertHandle Handle { get; } = handle;
        public Task Worker = Task.CompletedTask;
        public volatile bool Running = true, Stopping;
    }

    public async Task StartAsync(int? onlyProcessId = null)
    {
        if (onlyProcessId is <= 0) throw new ArgumentOutOfRangeException(nameof(onlyProcessId));
        await gate.WaitAsync();
        try
        {
            if (IsRunning) throw new InvalidOperationException("Monitor is already running.");
            await StopCore();
            WinDivertNative.VerifyFiles();
            var next = new ObservationSession(WinDivertNative.OpenFlow(onlyProcessId));
            LastError = null; session = next;
            next.Worker = Task.Factory.StartNew(() => Read(next), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        finally { gate.Release(); }
    }

    private void Read(ObservationSession current)
    {
        try
        {
            while (!current.Stopping)
            {
                if (!WinDivertNative.ReceiveFlow(current.Handle, IntPtr.Zero, 0, IntPtr.Zero, out var address))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (current.Stopping && error is 232 or 995 or 6) break;
                    throw new Win32Exception(error);
                }
                var record = Decode(address);
                if (record is null || current.Stopping) continue;
                pending.Enqueue(record);
                while (pending.Count > 2048 && pending.TryDequeue(out _)) Interlocked.Increment(ref skipped);
            }
        }
        catch (Exception ex)
        {
            if (!current.Stopping) LastError = ex is Win32Exception win32 ? $"Monitor stopped: Windows error {win32.NativeErrorCode}" : $"Monitor stopped: {ex.GetType().Name}";
        }
        finally { current.Running = false; current.Handle.Dispose(); }
    }

    internal static ObservedConnection? Decode(DivertAddress address, Func<int, DateTimeOffset, string?>? nameResolver = null)
    {
        if ((address.Flags & 0xff) != 2 || ((address.Flags >> 8) & 0xff) != 1 || (address.Flags & (1u << 17)) == 0
            || address.FlowProtocol is not (6 or 17) || address.FlowProcessId > int.MaxValue) return null;
        var time = DateTimeOffset.Now;
        if (address.Timestamp > 0) time += TimeSpan.FromSeconds((address.Timestamp - Stopwatch.GetTimestamp()) / (double)Stopwatch.Frequency);
        var pid = (int)address.FlowProcessId;
        return new ObservedConnection(time, pid, (nameResolver ?? ResolveName)(pid, time),
            WinDivertNative.FlowIp(address.FlowLocal0, address.FlowLocal1, address.FlowLocal2, address.FlowLocal3), address.FlowLocalPort,
            WinDivertNative.FlowIp(address.FlowRemote0, address.FlowRemote1, address.FlowRemote2, address.FlowRemote3), address.FlowRemotePort,
            address.FlowProtocol == 6 ? Transport.Tcp : Transport.Udp, (address.Flags & (1u << 18)) != 0);
    }

    private static string? ResolveName(int pid, DateTimeOffset time)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            // A delayed event must not acquire the name of a later process reusing its PID.
            if (process.StartTime.ToUniversalTime() > time.UtcDateTime.AddMilliseconds(5)) return null;
            var name = process.ProcessName;
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException) { return null; }
    }

    public bool TryRead(out ObservedConnection? connection) => pending.TryDequeue(out connection);
    public void Clear() { pending.Clear(); Interlocked.Exchange(ref skipped, 0); }
    public async Task StopAsync()
    {
        await gate.WaitAsync();
        try { await StopCore(); } finally { gate.Release(); }
    }
    private async Task StopCore()
    {
        var current = session; if (current is null) return;
        current.Stopping = true;
        try
        {
            if (!current.Handle.IsClosed && !WinDivertNative.WinDivertShutdown(current.Handle, WinDivertNative.ShutdownReceive)) current.Handle.Abort();
        }
        catch (ObjectDisposedException) { /* Worker already closed after an error. */ }
        await current.Worker;
        current.Handle.Dispose(); session = null;
    }
    public async ValueTask DisposeAsync() { await StopAsync(); gate.Dispose(); }
}
