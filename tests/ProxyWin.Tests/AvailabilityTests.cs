using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyWin.Core;
using ProxyWin.Windows;

internal static class AvailabilityTests
{
    private static readonly IPEndPoint Destination = new(IPAddress.Parse("203.0.113.10"), 443);
    private static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    public static async Task HttpSuccess()
    {
        foreach (var status in new[] { 200, 201, 204, 299 })
            await HttpReply($"HTTP/1.1 {status} Tunnel\r\n\r\n");
    }

    public static async Task HttpInterim()
    {
        await HttpReply("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Tunnel\r\n\r\n");
        await HttpReply("HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\nHTTP/1.1 204 Tunnel\r\n\r\n");
    }

    public static Task HttpHeaderBoundary()
    {
        const string start = "HTTP/1.1 200 Tunnel\r\nX-Padding: ";
        const string end = "\r\n\r\n";
        return HttpReply(start + new string('a', 16384 - start.Length - end.Length) + end);
    }

    private static async Task HttpReply(string header)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bypass = new SocketBypass();
        var payload = new byte[] { 0, 255, 1, 13, 10, 0, 42 };
        var peer = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
            var stream = accepted.GetStream();
            var one = new byte[1]; var ending = 0u;
            do
            {
                await stream.ReadExactlyAsync(one, timeout.Token);
                ending = (ending << 8) | one[0];
            } while (ending != 0x0d0a0d0a);
            // A single write tests that the CONNECT parser leaves tunnel bytes intact.
            await stream.WriteAsync(Encoding.ASCII.GetBytes(header).Concat(payload).ToArray(), timeout.Token);
        });
        try
        {
            using (var connection = await ProxyConnector.OpenAsync(new ProxyServer { Kind = ProxyKind.Http },
                (IPEndPoint)listener.LocalEndpoint, Destination, bypass, timeout.Token))
            {
                var received = new byte[payload.Length];
                await connection.Stream.ReadExactlyAsync(received, timeout.Token);
                Require(received.SequenceEqual(payload), "CONNECT consumed or altered initial tunnel bytes");
            }
            Require(bypass.Count == 0, "Successful CONNECT leaked its socket registration");
        }
        finally { timeout.Cancel(); await peer; }
    }

    public static async Task CancelHandshakes()
    {
        foreach (var kind in new[] { ProxyKind.Socks5, ProxyKind.Http })
        {
            for (var iteration = 0; iteration < 16; iteration++)
            {
                using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
                using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var stop = CancellationTokenSource.CreateLinkedTokenSource(watchdog.Token);
                var bypass = new SocketBypass();
                var opening = ProxyConnector.OpenAsync(new ProxyServer { Kind = kind },
                    (IPEndPoint)listener.LocalEndpoint, Destination, bypass, stop.Token);
                using var peer = await listener.AcceptTcpClientAsync(watchdog.Token);
                var first = new byte[1];
                await peer.GetStream().ReadExactlyAsync(first, watchdog.Token);
                stop.Cancel();
                try { using var unexpected = await opening; throw new Exception("Cancelled handshake succeeded"); }
                catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
                Require(bypass.Count == 0, "Cancelled handshake retained bypass registration");
            }
        }
    }

    public static async Task ConcurrentRelays()
    {
        const int waves = 4, concurrency = 32, size = 128 * 1024;
        await using var server = new TestProxy("concurrent", streaming: true);
        var bypass = new SocketBypass();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var watch = Stopwatch.StartNew();
        for (var wave = 0; wave < waves; wave++)
        {
            await Task.WhenAll(Enumerable.Range(0, concurrency).Select(async id =>
            {
                using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
                using var client = new TcpClient { NoDelay = true };
                await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, timeout.Token);
                using var accepted = await listener.AcceptTcpClientAsync(timeout.Token);
                using var proxy = await ProxyConnector.OpenAsync(new ProxyServer(),
                    new IPEndPoint(IPAddress.Loopback, server.Port), Destination, bypass, timeout.Token);
                long uploaded = 0, downloaded = 0;
                var relay = ProxyConnector.RelayAsync(accepted, proxy, (length, upload) =>
                {
                    if (upload) Interlocked.Add(ref uploaded, length); else Interlocked.Add(ref downloaded, length);
                }, timeout.Token);
                var payload = new byte[size];
                new Random(id + wave * concurrency).NextBytes(payload);
                var received = new byte[size];
                var stream = client.GetStream();
                async Task Send()
                {
                    await stream.WriteAsync(payload, timeout.Token);
                    client.Client.Shutdown(SocketShutdown.Send);
                }
                try
                {
                    await Task.WhenAll(Send(), stream.ReadExactlyAsync(received, timeout.Token).AsTask());
                    Require(await stream.ReadAsync(new byte[1], timeout.Token) == 0, "Half-close did not reach EOF");
                    await relay;
                    Require(payload.SequenceEqual(received), "Concurrent relay corrupted payload");
                    Require(uploaded == size && downloaded == size, "Relay byte accounting mismatch");
                }
                finally
                {
                    client.Dispose(); accepted.Dispose(); proxy.Dispose();
                    try { await relay; } catch (Exception) when (timeout.IsCancellationRequested) { }
                }
            }));
            Require(bypass.Count == 0, "Completed relay wave retained registrations");
        }
        Require(server.PeerErrors.IsEmpty, "Concurrent test peer reported errors");
        Console.WriteLine($"  {waves * concurrency} relays, {concurrency} concurrent; {waves * concurrency * size / 1048576} MiB verified each direction in {watch.Elapsed.TotalSeconds:F3}s");
    }

    public static async Task UdpCancellationBudget()
    {
        var budget = new DatagramBudget();
        var bypass = new SocketBypass();
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var flow = new FlowKey(IPAddress.Loopback, 51001, Destination.Address, 53, true);
        for (var iteration = 0; iteration < 32; iteration++)
        {
            Exception? failure = null;
            using var association = new UdpAssociation(flow, new ProxyServer(), (IPEndPoint)listener.LocalEndpoint,
                bypass, budget, _ => throw new Exception("Unexpected UDP reply"), (_, _) => { }, e => failure = e, watchdog.Token);
            using var control = await listener.AcceptTcpClientAsync(watchdog.Token);
            // The peer has not completed authentication: all datagrams remain queued.
            var payload = new byte[1024];
            for (var i = 0; i < 32; i++) Require(association.Enqueue(payload), "Queue filled before its declared bound");
            Require(!association.Enqueue(payload), "Queue exceeded its 32-datagram bound");
            association.Dispose(); association.Dispose();
            await association.Completion.WaitAsync(watchdog.Token);
            Require(!association.Enqueue(payload), "Disposed association accepted another datagram");
            Require(failure is null, "Normal UDP cancellation reported a failure");
            Require(bypass.Count == 0, "UDP cancellation leaked its TCP control registration");
            Require(budget.TryReserve(16 * 1024 * 1024), "Cancelled UDP queue leaked global budget");
            budget.Release(16 * 1024 * 1024);
        }
    }

    public static Task TcpCapacityRecovery()
    {
        var table = new TcpFlowTable();
        var route = new CapturePlan(new Profile { Rules = [new RoutingRule { Destinations = "*", Action = RuleAction.Block }] }).Entries[0];
        var key = new FlowKey(IPAddress.Loopback, 51000, Destination.Address, 443, false);
        var ports = new HashSet<int>();
        for (var i = 0; i < 16384; i++)
        {
            var flow = table.Create(key with { LocalPort = i + 1 }, route, 1, 10001, 10002);
            Require(flow is not null && ports.Add(flow.VirtualPort) && flow.VirtualPort is not (10001 or 10002), "Flow capacity or virtual-port uniqueness failed");
            flow!.LastSeen = Environment.TickCount64 - 31000;
        }
        Require(table.Create(key, route, 1, 10001, 10002) is null, "Flow table exceeded its bound");
        table.Sweep();
        Require(table.Create(key, route, 2, 10001, 10002) is not null, "Expired flow capacity did not recover");
        return Task.CompletedTask;
    }
}
