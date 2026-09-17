using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

// Local test doubles never connect to the requested destinations.
internal sealed class TestProxy : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> clients = [];
    private readonly Task loop;
    private readonly string label;
    private readonly bool http, echo;
    private readonly bool reject;
    private readonly bool streaming;
    private readonly string? username, password;
    public ConcurrentBag<string> RequestedDestinations { get; } = [];
    public ConcurrentQueue<string> PeerErrors { get; } = new();
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    public TestProxy(string label, bool http = false, bool echo = false, bool reject = false, bool streaming = false, string? username = null, string? password = null)
    {
        this.label = label; this.http = http; this.echo = echo; this.reject = reject;
        this.streaming = streaming; this.username = username; this.password = password;
        listener.Start(); loop = Accept();
    }
    private async Task Accept()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                clients.Add(Handle(client));
            }
        }
        catch (OperationCanceledException) { }
    }
    private async Task Handle(TcpClient client)
    {
        using (client)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(streaming ? 45 : 15));
            var token = timeout.Token;
            var stream = client.GetStream();
            try
            {
                if (http)
                {
                    var header = new StringBuilder();
                    var one = new byte[1];
                    while (!header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                    {
                        await stream.ReadExactlyAsync(one, token); header.Append((char)one[0]);
                        if (header.Length > 8192) throw new IOException("Large header");
                    }
                    if (!header.ToString().StartsWith("CONNECT ", StringComparison.Ordinal)) throw new IOException("Expected CONNECT");
                    RequestedDestinations.Add(header.ToString().Split(' ')[1]);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"), token);
                }
                else if (!echo)
                {
                    var hello = new byte[2]; await stream.ReadExactlyAsync(hello, token);
                    var methods = new byte[hello[1]]; await stream.ReadExactlyAsync(methods, token);
                    var method = (byte)(username is null ? 0 : 2);
                    if (!methods.Contains(method)) { await stream.WriteAsync(new byte[] { 5, 255 }, token); return; }
                    await stream.WriteAsync(new byte[] { 5, method }, token);
                    if (method == 2)
                    {
                        var auth = new byte[2]; await stream.ReadExactlyAsync(auth, token);
                        var user = new byte[auth[1]]; await stream.ReadExactlyAsync(user, token);
                        var length = new byte[1]; await stream.ReadExactlyAsync(length, token);
                        var pass = new byte[length[0]]; await stream.ReadExactlyAsync(pass, token);
                        var accepted = auth[0] == 1 && Encoding.UTF8.GetString(user) == username && Encoding.UTF8.GetString(pass) == password;
                        await stream.WriteAsync(new byte[] { 1, (byte)(accepted ? 0 : 1) }, token);
                        if (!accepted) return;
                    }
                    var request = new byte[4]; await stream.ReadExactlyAsync(request, token);
                    var requested = await ReadAddress(stream, request[3], token);
                    RequestedDestinations.Add(new IPEndPoint(new IPAddress(requested[..^2]), requested[^2] * 256 + requested[^1]).ToString());
                    if (reject) { await stream.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, token); return; }
                    if (request[1] == 3)
                    {
                        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
                        await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }, token);
                        var datagram = await udp.ReceiveAsync(token);
                        var offset = datagram.Buffer[3] == 1 ? 10 : 22;
                        var reply = datagram.Buffer[..offset].Concat(Encoding.ASCII.GetBytes(label + ":")).Concat(datagram.Buffer[offset..]).ToArray();
                        await udp.SendAsync(reply, datagram.RemoteEndPoint, token);
                        // Keep the association alive until its controlling TCP connection closes.
                        while (await stream.ReadAsync(new byte[1], token) != 0) { }
                        return;
                    }
                    if (request[1] != 1) throw new IOException("Expected CONNECT or UDP ASSOCIATE");
                    await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, token);
                }
                if (streaming)
                {
                    var buffer = new byte[65536]; int read;
                    while ((read = await stream.ReadAsync(buffer, token)) != 0) await stream.WriteAsync(buffer.AsMemory(0, read), token);
                    return;
                }
                var payload = new byte[4]; await stream.ReadExactlyAsync(payload, token);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(label + ":" + Encoding.ASCII.GetString(payload)), token);
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            catch (IOException ex) { PeerErrors.Enqueue(ex.GetType().Name + ": " + ex.Message); }
        }
    }
    private static async Task<byte[]> ReadAddress(NetworkStream stream, byte type, CancellationToken token)
    {
        var length = type switch { 1 => 4, 4 => 16, 3 => -1, _ => throw new IOException("Bad address type") };
        if (length < 0) { var b = new byte[1]; await stream.ReadExactlyAsync(b, token); length = b[0]; }
        var bytes = new byte[length + 2]; await stream.ReadExactlyAsync(bytes, token); return bytes;
    }
    private static async Task<byte[]> Handshake(NetworkStream stream, byte command, string ip, int port, CancellationToken token)
    {
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, token);
        var hello = new byte[2]; await stream.ReadExactlyAsync(hello, token);
        if (!hello.SequenceEqual(new byte[] { 5, 0 })) throw new IOException("Handshake failed");
        var address = IPAddress.Parse(ip).GetAddressBytes();
        var request = new byte[] { 5, command, 0, (byte)(address.Length == 4 ? 1 : 4) }.Concat(address).Concat(new byte[] { (byte)(port >> 8), (byte)port }).ToArray();
        await stream.WriteAsync(request, token);
        var reply = new byte[4]; await stream.ReadExactlyAsync(reply, token);
        if (reply[1] != 0) throw new IOException($"SOCKS failure {reply[1]}");
        return await ReadAddress(stream, reply[3], token);
    }
    public static async Task<string> SendTcp(int proxyPort, string ip, int port)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var token = timeout.Token;
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, proxyPort, token);
        var stream = client.GetStream(); await Handshake(stream, 1, ip, port, token);
        await stream.WriteAsync("ping"u8.ToArray(), token);
        using var output = new MemoryStream(); await stream.CopyToAsync(output, token);
        return Encoding.ASCII.GetString(output.ToArray());
    }
    public static async Task<string> SendUdp(int proxyPort, string ip, int port)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var token = timeout.Token;
        using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, proxyPort, token);
        var bound = await Handshake(client.GetStream(), 3, "0.0.0.0", 0, token);
        var relayPort = bound[^2] * 256 + bound[^1];
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var packet = new byte[] { 0, 0, 0, 1 }.Concat(IPAddress.Parse(ip).GetAddressBytes()).Concat(new byte[] { (byte)(port >> 8), (byte)port }).Concat("ping"u8.ToArray()).ToArray();
        await udp.SendAsync(packet, new IPEndPoint(IPAddress.Loopback, relayPort), token);
        var reply = await udp.ReceiveAsync(token);
        return Encoding.ASCII.GetString(reply.Buffer[10..]);
    }
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop(); await loop;
        try { await Task.WhenAll(clients); } catch (OperationCanceledException) { }
        shutdown.Dispose();
    }
}
