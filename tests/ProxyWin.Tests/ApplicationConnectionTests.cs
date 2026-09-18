using System.Net;
using System.Net.Sockets;
using ProxyWin.Windows;

internal static class ApplicationConnectionTests
{
    public static async Task Lifetime()
    {
        var initial = ApplicationConnection.Bypass.Count;
        foreach (var address in Socket.OSSupportsIPv6 ? new[] { IPAddress.Loopback, IPAddress.IPv6Loopback } : [IPAddress.Loopback])
        {
            var listener = new TcpListener(address, 0); listener.Start();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                var accepted = listener.AcceptTcpClientAsync(timeout.Token);
                var stream = await ApplicationConnection.ConnectAsync(new DnsEndPoint(address.ToString(), ((IPEndPoint)listener.LocalEndpoint).Port), timeout.Token);
                using var peer = await accepted;
                var port = ((IPEndPoint)peer.Client.RemoteEndPoint!).Port;
                try
                {
                    if (!ApplicationConnection.Bypass.Contains(false, port) || ApplicationConnection.Bypass.Contains(true, port))
                        throw new Exception("TCP ownership not scoped to the registered transport");
                    using var other = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
                    try { other.Bind(new IPEndPoint(IPAddress.Any, port)); throw new Exception("Another TCP socket could reuse the managed port"); }
                    catch (SocketException) { }
                    await stream.WriteAsync("ping"u8.ToArray(), timeout.Token);
                    var bytes = new byte[4]; await peer.GetStream().ReadExactlyAsync(bytes, timeout.Token);
                    if (!bytes.AsSpan().SequenceEqual("ping"u8)) throw new Exception("Transport payload changed");
                }
                finally { if (address.Equals(IPAddress.Loopback)) stream.Dispose(); else await stream.DisposeAsync(); }
                if (ApplicationConnection.Bypass.Contains(false, port)) throw new Exception("Disposed stream retained a bypass");
            }
            finally { listener.Stop(); }
        }
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        try { await ApplicationConnection.ConnectAsync(new DnsEndPoint("127.0.0.1", 1), cancelled.Token); throw new Exception("Cancellation ignored"); }
        catch (OperationCanceledException) { }
        using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        using var failureTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await ApplicationConnection.ConnectAsync(new DnsEndPoint("127.0.0.1", ((IPEndPoint)reserved.LocalEndPoint!).Port), failureTimeout.Token); throw new Exception("Non-listening peer accepted"); }
        catch (SocketException) { }
        if (ApplicationConnection.Bypass.Count != initial) throw new Exception("Failed/cancelled connect leaked a bypass");
    }
}
