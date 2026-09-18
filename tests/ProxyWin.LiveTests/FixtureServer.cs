using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal sealed class FixtureServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> peers = [];
    private readonly Task accept;
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public long Connects, Requests, Bytes;
    public FixtureServer() { listener.Start(); accept = Accept(); }
    private async Task Accept()
    {
        try { while (!stop.IsCancellationRequested) { var client = await listener.AcceptTcpClientAsync(stop.Token); peers.Add(Serve(client)); } }
        catch (OperationCanceledException) { }
    }
    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                var stream = client.GetStream();
                var header = await Header(stream, stop.Token);
                if (header.StartsWith("CONNECT ", StringComparison.Ordinal))
                {
                    // No forwarding: only the fixture's documentation endpoint is accepted.
                    if (!header.StartsWith("CONNECT 203.0.113.10:18080 ", StringComparison.Ordinal)) throw new IOException("Unexpected CONNECT target");
                    Interlocked.Increment(ref Connects);
                    await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), stop.Token);
                    header = await Header(stream, stop.Token);
                }
                var target = header.Split(' ')[1];
                var size = target.StartsWith("/bytes/", StringComparison.Ordinal) ? int.Parse(target.Split('/')[2].Split('?')[0]) : 0;
                if (size is < 0 or > 33554432) throw new IOException("Invalid fixture size");
                var body = size == 0 ? Encoding.UTF8.GetBytes("<!doctype html><title>ProxyWin Whale fixture</title>ProxyWin fixture") : new byte[size];
                if (size != 0) for (var i = 0; i < size; i++) body[i] = (byte)(i % 251);
                var response = $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nContent-Type: {(size == 0 ? "text/html" : "application/octet-stream")}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), stop.Token);
                await stream.WriteAsync(body, stop.Token);
                Interlocked.Increment(ref Requests); Interlocked.Add(ref Bytes, body.Length);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { }
        }
    }
    private static async Task<string> Header(NetworkStream stream, CancellationToken ct)
    {
        var bytes = new List<byte>(); var one = new byte[1];
        while (bytes.Count < 16384)
        {
            if (await stream.ReadAsync(one, ct) == 0) throw new IOException("Peer closed");
            bytes.Add(one[0]);
            if (bytes.Count >= 4 && bytes[^4] == 13 && bytes[^3] == 10 && bytes[^2] == 13 && bytes[^1] == 10) return Encoding.ASCII.GetString(bytes.ToArray());
        }
        throw new IOException("Header too long");
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop(); await accept; await Task.WhenAll(peers); stop.Dispose();
    }
}
