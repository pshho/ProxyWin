using System.Net;
using System.Net.Sockets;
using ProxyWin.Windows;

internal static class SocketOwnerAvailabilityTests
{
    public static Task EndpointMatching()
    {
        const int port = 1080;
        var rows = new[]
        {
            new SocketOwners.Owner(IPAddress.Loopback, port, null, 0, 1, true),
            new SocketOwners.Owner(IPAddress.Parse("127.0.0.2"), port, null, 0, 2, true),
            new SocketOwners.Owner(IPAddress.Any, port, null, 0, 3, true),
            new SocketOwners.Owner(IPAddress.IPv6Loopback, port, null, 0, 4, true),
            new SocketOwners.Owner(IPAddress.Parse("::2"), port, null, 0, 5, true),
            new SocketOwners.Owner(IPAddress.IPv6Any, port, null, 0, 6, true),
            new SocketOwners.Owner(IPAddress.Loopback, port + 1, null, 0, 7, true),
            new SocketOwners.Owner(IPAddress.Loopback, port, IPAddress.Parse("203.0.113.10"), 443, 8, false)
        };

        var ipv4 = SocketOwners.MatchLocalProxyOwners(rows, [new IPEndPoint(IPAddress.Loopback, port)]);
        if (!ipv4.SetEquals([1, 3]))
            throw new Exception("IPv4 proxy matched another address, family, port, or a non-listening socket");

        var ipv6 = SocketOwners.MatchLocalProxyOwners(rows, [new IPEndPoint(IPAddress.IPv6Loopback, port)]);
        if (!ipv6.SetEquals([4, 6]))
            throw new Exception("IPv6 proxy matched another address, family, port, or a non-listening socket");

        var both = SocketOwners.MatchLocalProxyOwners(rows,
            [new IPEndPoint(IPAddress.Loopback, port), new IPEndPoint(IPAddress.IPv6Loopback, port)]);
        if (!both.SetEquals([1, 3, 4, 6]))
            throw new Exception("Multiple local proxy endpoints did not retain their distinct listener owners");

        return Task.CompletedTask;
    }

    public static async Task ActualListeners()
    {
        static async Task Check(IPAddress bind, IPAddress destination, bool? dualMode = null)
        {
            var listener = new TcpListener(bind, 0) { ExclusiveAddressUse = true };
            if (dualMode is { } mode) listener.Server.DualMode = mode;
            listener.Start();
            try
            {
                var endpoint = new IPEndPoint(destination, ((IPEndPoint)listener.LocalEndpoint).Port);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var accept = listener.AcceptTcpClientAsync(timeout.Token);
                using var client = new TcpClient(destination.AddressFamily);
                await client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
                using var peer = await accept;
                if (!SocketOwners.LocalProxyOwners([endpoint]).Contains(Environment.ProcessId))
                    throw new Exception($"Owner lookup missed {bind} (dual mode {dualMode?.ToString() ?? "n/a"}) serving {endpoint}");
            }
            finally { listener.Stop(); }
        }

        await Check(IPAddress.Loopback, IPAddress.Loopback);
        await Check(IPAddress.Parse("127.0.0.2"), IPAddress.Parse("127.0.0.2"));
        await Check(IPAddress.Any, IPAddress.Loopback);
        if (!Socket.OSSupportsIPv6) return;
        await Check(IPAddress.IPv6Loopback, IPAddress.IPv6Loopback, dualMode: false);
        await Check(IPAddress.IPv6Any, IPAddress.IPv6Loopback, dualMode: false);
        await Check(IPAddress.IPv6Any, IPAddress.IPv6Loopback, dualMode: true);
        await Check(IPAddress.IPv6Any, IPAddress.Loopback, dualMode: true);
    }
}
