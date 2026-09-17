using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public readonly record struct RelayStatistics(long Uploaded, long Downloaded, long Dropped, long Errors, int TcpConnections, int UdpAssociations, long Blocked = 0);

public sealed class DivertEngine : IAsyncDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private Session? session;
    private RelayStatistics last;
    public bool IsRunning => session is { Stopping: false };
    public RelayStatistics Statistics => session?.Statistics ?? last;
    public event Action<string>? Log;
    public event Action? Exited;

    private sealed class Session(CapturePlan plan, Dictionary<string, IPEndPoint> servers)
    {
        public CapturePlan Plan { get; } = plan;
        public Dictionary<string, IPEndPoint> Servers { get; } = servers;
        public CancellationTokenSource Stop { get; } = new();
        public TcpListener Listener4 { get; } = new(IPAddress.Any, 0);
        public TcpListener? Listener6 { get; } = Socket.OSSupportsIPv6 ? new(IPAddress.IPv6Any, 0) : null;
        public int Port4, Port6;
        public DivertHandle? Handle;
        public Task Capture = Task.CompletedTask, Accept4 = Task.CompletedTask, Accept6 = Task.CompletedTask, Maintenance = Task.CompletedTask;
        public TcpFlowTable Flows { get; } = new();
        public SocketBypass Bypass { get; } = new();
        public DatagramBudget Budget { get; } = new();
        public ConcurrentDictionary<FlowKey, UdpAssociation> Udp { get; } = new();
        public ConcurrentDictionary<int, Task> Tcp { get; } = new();
        public SemaphoreSlim TcpSlots { get; } = new(2048, 2048);
        public ConcurrentDictionary<FlowKey, long> Passthrough { get; } = new();
        public long Uploaded, Downloaded, Dropped, Errors, LastLog, Blocked;
        public volatile bool Stopping;
        public RelayStatistics Statistics => new(Interlocked.Read(ref Uploaded), Interlocked.Read(ref Downloaded), Interlocked.Read(ref Dropped), Interlocked.Read(ref Errors), Tcp.Count, Udp.Count, Interlocked.Read(ref Blocked));
        public void Count(int length, bool upload)
        {
            if (upload) Interlocked.Add(ref Uploaded, length); else Interlocked.Add(ref Downloaded, length);
        }
    }

    public static void CheckDriver() => WinDivertNative.VerifyFiles();
    public static void CheckFilter(string filter) { CheckDriver(); WinDivertNative.ValidateFilter(filter); }

    public async Task StartAsync(Profile profile)
    {
        var plan = new CapturePlan(profile);
        await gate.WaitAsync();
        try
        {
            if (session is not null) throw new InvalidOperationException("Rules are already active.");
            CheckDriver();
            var servers = new Dictionary<string, IPEndPoint>();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            foreach (var proxy in plan.Entries.Select(e => e.Proxy).OfType<ProxyServer>().DistinctBy(p => p.Id))
            {
                var addresses = await Dns.GetHostAddressesAsync(proxy.Host, timeout.Token);
                var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault()
                    ?? throw new IOException($"Cannot resolve proxy '{proxy.Name}'.");
                servers.Add(proxy.Id, new IPEndPoint(address, proxy.Port));
            }
            var state = new Session(plan, servers);
            try
            {
                state.Listener4.ExclusiveAddressUse = true;
                state.Listener4.Server.ReceiveBufferSize = 262144; state.Listener4.Server.SendBufferSize = 262144;
                state.Listener4.Start(512);
                state.Port4 = ((IPEndPoint)state.Listener4.LocalEndpoint).Port;
                if (state.Listener6 is not null)
                {
                    state.Listener6.Server.DualMode = false; state.Listener6.ExclusiveAddressUse = true;
                    state.Listener6.Server.ReceiveBufferSize = 262144; state.Listener6.Server.SendBufferSize = 262144;
                    state.Listener6.Start(512);
                    state.Port6 = ((IPEndPoint)state.Listener6.LocalEndpoint).Port;
                }
                else state.Port6 = state.Port4;
                var filter = plan.Filter(state.Port4, state.Port6);
                WinDivertNative.ValidateFilter(filter);
                state.Handle = WinDivertNative.Open(filter);
                session = state;
                state.Accept4 = Accept(state, state.Listener4);
                if (state.Listener6 is not null) state.Accept6 = Accept(state, state.Listener6);
                state.Capture = Task.Factory.StartNew(() => Capture(state), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                state.Maintenance = Maintain(state);
                Log?.Invoke("Rules active. PROXY applies to new TCP connections.");
            }
            catch
            {
                state.Listener4.Stop(); state.Listener6?.Stop(); state.Handle?.Dispose(); state.Stop.Dispose(); state.TcpSlots.Dispose();
                session = null; throw;
            }
        }
        finally { gate.Release(); }
    }

    private void Failure(Session state, Exception ex)
    {
        Interlocked.Increment(ref state.Errors);
        var now = Environment.TickCount64;
        if (now - Interlocked.Read(ref state.LastLog) < 1000) return;
        Interlocked.Exchange(ref state.LastLog, now);
        // Only typed error summaries: upstream bodies and authentication bytes are never logged.
        Log?.Invoke(ex is SocketException socket ? $"Network error: {socket.SocketErrorCode}" : $"Relay error: {ex.GetType().Name}. Check the proxy and credentials.");
    }

    private async Task Accept(Session state, TcpListener listener)
    {
        try
        {
            while (!state.Stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(state.Stop.Token); client.NoDelay = true;
                var flow = state.Flows.Accept((IPEndPoint)client.Client.RemoteEndPoint!, (IPEndPoint)client.Client.LocalEndPoint!);
                if (flow is null || !state.TcpSlots.Wait(0))
                {
                    if (flow is not null) Volatile.Write(ref flow.Closed, Environment.TickCount64);
                    client.Dispose(); Interlocked.Increment(ref state.Dropped); continue;
                }
                var work = RelayTcp(state, flow, client);
                state.Tcp[flow.VirtualPort] = work;
                _ = work.ContinueWith(_ => state.Tcp.TryRemove(flow.VirtualPort, out var removed), TaskScheduler.Default);
            }
        }
        catch (Exception ex) when (state.Stop.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
        catch (Exception ex) { Failure(state, ex); _ = StopAfterFailure(state); }
    }

    private async Task RelayTcp(Session state, TcpFlow flow, TcpClient client)
    {
        using (client)
        {
            try
            {
                using var proxy = await ProxyConnector.OpenAsync(flow.Route.Proxy!, state.Servers[flow.Route.Proxy!.Id],
                    new IPEndPoint(flow.Key.RemoteAddress, flow.Key.RemotePort), state.Bypass, state.Stop.Token);
                await ProxyConnector.RelayAsync(client, proxy, state.Count, state.Stop.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                if (!state.Stop.IsCancellationRequested) Failure(state, ex);
                try { client.Client.LingerState = new LingerOption(true, 0); } catch (SocketException) { }
            }
            finally { Volatile.Write(ref flow.Closed, Environment.TickCount64); state.TcpSlots.Release(); }
        }
    }

    private unsafe void Capture(Session state)
    {
        var bytes = new byte[WinDivertNative.BufferSize];
        var addresses = new DivertAddress[WinDivertNative.BatchSize];
        var sending = new DivertAddress[WinDivertNative.BatchSize];
        try
        {
            fixed (byte* pointer = bytes)
            {
                while (true)
                {
                    uint addressLength = (uint)(addresses.Length * 80);
                    if (!WinDivertNative.WinDivertRecvEx(state.Handle!, pointer, (uint)bytes.Length, out var length, 0, addresses, ref addressLength, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (state.Stopping && error is 232 or 995 or 6) break;
                        throw new Win32Exception(error);
                    }
                    var offset = 0; var write = 0; var count = 0;
                    for (var i = 0; i < addressLength / 80 && offset < length; i++)
                    {
                        var remaining = bytes.AsSpan(offset, (int)length - offset);
                        if (!IpPacket.TryParse(remaining, out var packet)) { Interlocked.Increment(ref state.Dropped); break; }
                        var frame = remaining[..packet.Length]; var address = addresses[i];
                        var decision = ProcessPacket(state, packet, frame, ref address);
                        if (decision != 0)
                        {
                            if (decision == 2 && !WinDivertNative.WinDivertHelperCalcChecksums(pointer + offset, (uint)packet.Length, ref address, 0))
                                throw new IOException("Packet checksum failed.");
                            frame.CopyTo(bytes.AsSpan(write)); write += packet.Length; sending[count++] = address;
                        }
                        offset += packet.Length;
                    }
                    if (count > 0 && (!WinDivertNative.WinDivertSendEx(state.Handle!, pointer, (uint)write, out var sent, 0, sending, (uint)(count * 80), IntPtr.Zero) || sent != write))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Packet reinjection failed.");
                }
            }
        }
        catch (Exception ex) { if (!state.Stopping) { Failure(state, ex); _ = StopAfterFailure(state); } }
    }

    // 0: consumed/dropped; 1: pass untouched; 2: translated, checksum required.
    private int ProcessPacket(Session state, IpPacket packet, Span<byte> bytes, ref DivertAddress address)
    {
        if (packet.Fragmented)
        {
            if (packet.Protocol is 1 or 58) return 1; // Never consume ICMP as a TCP/UDP rule.
            Interlocked.Increment(ref state.Dropped); return 0;
        }
        var key = packet.Key(bytes);
        if (packet.Tcp && (key.LocalPort == state.Port4 || key.LocalPort == state.Port6))
        {
            var flow = state.Flows.FindVirtual(key.RemotePort);
            if (flow is null || !key.RemoteAddress.Equals(flow.Key.RemoteAddress) || !key.LocalAddress.Equals(flow.Key.LocalAddress)) return 1;
            packet.Rewrite(bytes, flow.Key.RemoteAddress, flow.Key.RemotePort, flow.Key.LocalAddress, flow.Key.LocalPort);
            address.Inbound(); return 2;
        }
        if (state.Bypass.Contains(key.Udp, key.LocalPort)) return 1;
        var syn = packet.Tcp && (bytes[packet.TransportOffset + 13] & 0x12) == 0x02;
        if (packet.Tcp && state.Flows.Find(key) is { } existing && (!syn || existing.Sequence == BinaryPrimitives.ReadUInt32BigEndian(bytes[(packet.TransportOffset + 4)..])))
        {
            Volatile.Write(ref existing.LastSeen, Environment.TickCount64);
            packet.Rewrite(bytes, key.RemoteAddress, existing.VirtualPort, key.LocalAddress, key.LocalAddress.GetAddressBytes().Length == 4 ? state.Port4 : state.Port6);
            address.Inbound(); return 2;
        }
        if (state.Stopping) { Interlocked.Increment(ref state.Dropped); return 0; }
        if (packet.Udp && state.Udp.TryGetValue(key, out var association))
        {
            // UDP ports can be reused by another process while an association is idle.
            // When process rules are enabled, correctness takes priority over lookup cost.
            if (state.Plan.NeedsProcessLookup)
            {
                var currentOwner = SocketOwners.Find(key);
                if (currentOwner is null) { Interlocked.Increment(ref state.Dropped); return 0; }
                var currentRoute = state.Plan.Match(key.RemoteAddress, key.RemotePort, true, SocketOwners.Name(currentOwner));
                if (currentRoute?.Action != RuleAction.Proxy || currentRoute.Proxy?.Id != association.ProxyId)
                {
                    association.Dispose();
                    if (currentRoute?.Action == RuleAction.Block) { Interlocked.Increment(ref state.Blocked); return 0; }
                    if (currentRoute is null || currentRoute.Action == RuleAction.Direct) return 1;
                    Interlocked.Increment(ref state.Dropped); return 0;
                }
            }
            if (!association.Enqueue(bytes[packet.PayloadOffset..])) Interlocked.Increment(ref state.Dropped);
            return 0;
        }
        if (packet.Tcp && !syn && state.Passthrough.ContainsKey(key)) { state.Passthrough[key] = Environment.TickCount64; return 1; }
        var firstCandidate = state.Plan.Entries.FirstOrDefault(e => e.Matches(key.RemoteAddress, key.RemotePort, key.Udp));
        if (firstCandidate is { Action: RuleAction.Direct } && firstCandidate.Rule.ProcessName.Length == 0)
        {
            // An unconditional first DIRECT rule must not depend on later process rules
            // or on whether a short-lived socket's owner can still be queried.
            if (packet.Tcp && state.Passthrough.Count < 32768) state.Passthrough[key] = Environment.TickCount64;
            return 1;
        }
        var needsOwner = firstCandidate?.Rule.ProcessName.Length > 0;
        HashSet<int> localProxyPids = state.Servers.Count == 0 ? [] : SocketOwners.LocalProxyOwners(state.Servers.Values);
        var owner = needsOwner || localProxyPids.Count > 0 ? SocketOwners.Find(key) : null;
        var excluded = owner is { } pid && (pid == Environment.ProcessId || localProxyPids.Contains(pid));
        // If a local proxy exists but attribution fails, do not risk recursively redirecting it.
        var unknownLocal = localProxyPids.Count > 0 && owner is null;
        if (unknownLocal || (owner is null && needsOwner))
        {
            Interlocked.Increment(ref state.Dropped);
            Failure(state, new IOException("Cannot identify the connection owner."));
            return 0;
        }
        var route = excluded ? null : state.Plan.Match(key.RemoteAddress, key.RemotePort, key.Udp, SocketOwners.Name(owner));
        if (route?.Action == RuleAction.Block)
        {
            Interlocked.Increment(ref state.Blocked);
            return 0;
        }
        if (route is null || route.Action == RuleAction.Direct || (packet.Tcp && !syn))
        {
            if (packet.Tcp && state.Passthrough.Count < 32768) state.Passthrough[key] = Environment.TickCount64;
            return 1;
        }
        if (packet.Tcp)
        {
            var flow = state.Flows.Create(key, route, BinaryPrimitives.ReadUInt32BigEndian(bytes[(packet.TransportOffset + 4)..]), state.Port4, state.Port6);
            if (flow is null) { Interlocked.Increment(ref state.Dropped); return 0; }
            packet.Rewrite(bytes, key.RemoteAddress, flow.VirtualPort, key.LocalAddress, key.LocalAddress.GetAddressBytes().Length == 4 ? state.Port4 : state.Port6);
            address.Inbound(); return 2;
        }
        if (state.Udp.Count >= 512) { Interlocked.Increment(ref state.Dropped); return 0; }
        var replyAddress = address; replyAddress.Inbound();
        var udp = new UdpAssociation(key, route.Proxy!, state.Servers[route.Proxy!.Id], state.Bypass, state.Budget,
            reply => SendUdpReply(state, reply, replyAddress), state.Count, ex => Failure(state, ex), state.Stop.Token);
        state.Udp[key] = udp;
        if (!udp.Enqueue(bytes[packet.PayloadOffset..])) Interlocked.Increment(ref state.Dropped);
        return 0;
    }

    private static unsafe void SendUdpReply(Session state, byte[] bytes, DivertAddress address)
    {
        fixed (byte* packet = bytes)
        {
            if (!WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)bytes.Length, ref address, 0)
                || !WinDivertNative.WinDivertSend(state.Handle!, packet, (uint)bytes.Length, out var sent, ref address) || sent != bytes.Length)
                throw new IOException("UDP reply injection failed.");
        }
    }

    private async Task Maintain(Session state)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (await timer.WaitForNextTickAsync(state.Stop.Token))
            {
                state.Flows.Sweep(); var now = Environment.TickCount64;
                foreach (var pair in state.Passthrough.Where(p => now - p.Value > 30000)) state.Passthrough.TryRemove(pair.Key, out _);
                foreach (var pair in state.Udp.Where(p => p.Value.Completion.IsCompleted || now - Volatile.Read(ref p.Value.LastSeen) > 120000))
                {
                    if (state.Udp.TryRemove(pair.Key, out var flow)) { flow.Dispose(); await flow.Completion; }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task StopAfterFailure(Session failed)
    {
        // Wait until the capture callback returns before StopAsync joins its worker.
        await Task.Yield();
        if (ReferenceEquals(session, failed)) { await StopAsync(); Exited?.Invoke(); }
    }

    public async Task StopAsync()
    {
        await gate.WaitAsync();
        try
        {
            var state = session; if (state is null) return;
            state.Stopping = true; state.Stop.Cancel(); state.Listener4.Stop(); state.Listener6?.Stop();
            try
            {
                await Task.WhenAll(state.Accept4, state.Accept6, state.Maintenance);
                foreach (var flow in state.Udp.Values) flow.Dispose();
                await Task.WhenAll(state.Tcp.Values.Concat(state.Udp.Values.Select(f => f.Completion)));
            }
            finally
            {
                if (!WinDivertNative.WinDivertShutdown(state.Handle!, WinDivertNative.ShutdownReceive)) state.Handle!.Abort();
                await state.Capture;
                state.Handle!.Dispose(); state.Stop.Dispose(); state.TcpSlots.Dispose();
                last = state.Statistics with { TcpConnections = 0, UdpAssociations = 0 }; session = null;
                Log?.Invoke("Rules stopped. Capture released.");
            }
        }
        finally { gate.Release(); }
    }
    public async ValueTask DisposeAsync() { await StopAsync(); gate.Dispose(); }
}
