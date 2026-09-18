using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyWin.Core;
using ProxyWin.Windows;

internal static class HttpFailureTests
{
    public static async Task StatusCodes()
    {
        var reset = RelayDiagnostics.Describe(new IOException("SECRET_BODY", new SocketException((int)SocketError.ConnectionReset)));
        if (!reset.Contains("ConnectionReset") || reset.Contains("SECRET")) throw new Exception("Socket cause lost or sensitive message exposed");
        if (RelayDiagnostics.Describe(new IOException("SECRET_BODY")).Contains("SECRET")) throw new Exception("Untrusted exception text exposed");
        if (!RelayDiagnostics.Describe(new ConnectionOwnerException()).Contains("connection owner")) throw new Exception("Local process attribution failure hidden");
        foreach (var status in new[] { 403, 407, 502 })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var peer = Task.Run(async () =>
            {
                using var client = await listener.AcceptTcpClientAsync(timeout.Token);
                var stream = client.GetStream(); var bytes = new List<byte>(); var one = new byte[1];
                while (!Encoding.ASCII.GetString(bytes.ToArray()).EndsWith("\r\n\r\n", StringComparison.Ordinal))
                { await stream.ReadExactlyAsync(one, timeout.Token); bytes.Add(one[0]); }
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} SECRET_REASON\r\nX-Secret: SECRET_HEADER\r\nContent-Length: 11\r\n\r\nSECRET_BODY"), timeout.Token);
            });
            try
            {
                var proxy = new ProxyServer { Kind = ProxyKind.Http, Host = "127.0.0.1", Port = ((IPEndPoint)listener.LocalEndpoint).Port, Username = "secret-user", Password = "secret-password" };
                try
                {
                    using var connection = await ProxyConnector.OpenAsync(proxy, (IPEndPoint)listener.LocalEndpoint,
                        new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443), new SocketBypass(), timeout.Token);
                    throw new Exception("HTTP rejection accepted");
                }
                catch (IOException ex)
                {
                    if (!ex.Message.Contains(status.ToString(), StringComparison.Ordinal)) throw new Exception($"HTTP {status} was hidden by: {ex.Message}");
                    if (ex.Message.Contains("SECRET", StringComparison.OrdinalIgnoreCase)) throw new Exception("Sensitive response was exposed");
                }
                await peer;
            }
            finally { listener.Stop(); }
        }
    }
}
