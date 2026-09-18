using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public sealed class SocketBypass
{
    private readonly ConcurrentDictionary<(bool Udp, int Port), long> ports = new();
    private long generation;
    internal int Count => ports.Count;
    public bool Contains(bool udp, int port) => ports.ContainsKey((udp, port));
    public IDisposable Register(bool udp, int port)
    {
        var key = (udp, port); var id = Interlocked.Increment(ref generation);
        ports[key] = id;
        return new Registration(() => ((ICollection<KeyValuePair<(bool Udp, int Port), long>>)ports).Remove(new(key, id)));
    }
    private sealed class Registration(Action release) : IDisposable
    {
        private Action? action = release;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
}

public sealed class ProxyConnection(TcpClient client, IDisposable registration) : IDisposable
{
    public TcpClient Client { get; } = client;
    public NetworkStream Stream => Client.GetStream();
    public void Dispose() { Client.Dispose(); registration.Dispose(); }
}

public static class ProxyConnector
{
    public static async Task<ProxyConnection> OpenAsync(ProxyServer proxy, IPEndPoint server, IPEndPoint destination,
        SocketBypass bypass, CancellationToken token, bool udpAssociate = false)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var client = new TcpClient(server.AddressFamily) { NoDelay = true, ExclusiveAddressUse = true, SendBufferSize = 262144, ReceiveBufferSize = 262144 };
        client.Client.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
        var lease = bypass.Register(false, ((IPEndPoint)client.Client.LocalEndPoint!).Port);
        var connection = new ProxyConnection(client, lease);
        var connected = false;
        try
        {
            await client.ConnectAsync(server.Address, server.Port, timeout.Token);
            connected = true;
            if (proxy.Kind == ProxyKind.Socks5)
            {
                await AuthenticateAsync(connection.Stream, proxy, timeout.Token);
                if (!udpAssociate) await SocksCommandAsync(connection.Stream, 1, destination, timeout.Token);
            }
            else
            {
                if (udpAssociate) throw new NotSupportedException("HTTP proxies do not support UDP.");
                var authority = destination.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{destination.Address}]:{destination.Port}" : destination.ToString();
                var auth = proxy.Username.Length == 0 ? "" : $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes(proxy.Username + ":" + proxy.Password))}\r\n";
                var request = Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n");
                await connection.Stream.WriteAsync(request, timeout.Token);
                // Do not over-read tunnel bytes which can immediately follow the headers.
                var header = new byte[16384]; var count = 0;
                while (count < header.Length)
                {
                    await connection.Stream.ReadExactlyAsync(header.AsMemory(count, 1), timeout.Token); count++;
                    if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                var firstLine = Encoding.ASCII.GetString(header, 0, count).Split("\r\n")[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (count == header.Length || firstLine.Length < 2 || !firstLine[0].StartsWith("HTTP/1.", StringComparison.Ordinal)
                    || !int.TryParse(firstLine[1], out var status) || status is < 100 or > 599)
                    throw new HttpConnectException(null);
                if (status != 200) throw new HttpConnectException(status);
            }
            return connection;
        }
        catch (IOException ex) when (connected) { connection.Dispose(); throw new ProxyHandshakeException(proxy.Kind, ex); }
        catch { connection.Dispose(); throw; }
    }

    private static async Task AuthenticateAsync(NetworkStream stream, ProxyServer proxy, CancellationToken token)
    {
        var method = (byte)(proxy.Username.Length == 0 ? 0 : 2);
        await stream.WriteAsync(new byte[] { 5, 1, method }, token);
        var reply = new byte[2]; await stream.ReadExactlyAsync(reply, token);
        if (reply[0] != 5 || reply[1] != method) throw new IOException("SOCKS5 authentication method rejected.");
        if (method == 0) return;
        var username = Encoding.UTF8.GetBytes(proxy.Username); var password = Encoding.UTF8.GetBytes(proxy.Password);
        var auth = new byte[3 + username.Length + password.Length]; auth[0] = 1; auth[1] = (byte)username.Length;
        username.CopyTo(auth, 2); auth[2 + username.Length] = (byte)password.Length; password.CopyTo(auth, 3 + username.Length);
        try { await stream.WriteAsync(auth, token); }
        finally { Array.Clear(auth); Array.Clear(password); }
        await stream.ReadExactlyAsync(reply, token);
        if (reply[0] != 1 || reply[1] != 0) throw new IOException("SOCKS5 authentication failed.");
    }

    public static async Task<(string Host, int Port)> SocksCommandAsync(NetworkStream stream, byte command, IPEndPoint destination, CancellationToken token)
    {
        var address = EncodeAddress(destination);
        await stream.WriteAsync(new byte[] { 5, command, 0 }.Concat(address).ToArray(), token);
        var header = new byte[4]; await stream.ReadExactlyAsync(header, token);
        if (header[0] != 5 || header[1] != 0 || header[2] != 0) throw new IOException($"SOCKS5 connection rejected (status {header[1]}).");
        string host;
        if (header[3] is 1 or 4)
        {
            var bytes = new byte[header[3] == 1 ? 4 : 16]; await stream.ReadExactlyAsync(bytes, token);
            host = new IPAddress(bytes).ToString();
        }
        else if (header[3] == 3)
        {
            var length = new byte[1]; await stream.ReadExactlyAsync(length, token);
            if (length[0] == 0) throw new IOException("SOCKS5 relay address is empty.");
            var bytes = new byte[length[0]]; await stream.ReadExactlyAsync(bytes, token); host = Encoding.ASCII.GetString(bytes);
        }
        else throw new IOException("Invalid SOCKS5 address.");
        var port = new byte[2]; await stream.ReadExactlyAsync(port, token);
        return (host, BinaryPrimitives.ReadUInt16BigEndian(port));
    }

    public static byte[] EncodeAddress(IPEndPoint endpoint)
    {
        var ip = endpoint.Address.GetAddressBytes(); var result = new byte[1 + ip.Length + 2];
        result[0] = (byte)(ip.Length == 4 ? 1 : 4); ip.CopyTo(result, 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(1 + ip.Length), (ushort)endpoint.Port); return result;
    }

    public static bool TryDecodeDatagram(ReadOnlySpan<byte> datagram, out IPEndPoint? source, out int payloadOffset)
    {
        source = null; payloadOffset = 0;
        if (datagram.Length < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0) return false;
        var addressLength = datagram[3] switch { 1 => 4, 4 => 16, _ => 0 };
        if (addressLength == 0 || datagram.Length < 6 + addressLength) return false;
        source = new IPEndPoint(new IPAddress(datagram.Slice(4, addressLength)), BinaryPrimitives.ReadUInt16BigEndian(datagram[(4 + addressLength)..]));
        payloadOffset = 6 + addressLength; return true;
    }

    public static async Task RelayAsync(TcpClient client, ProxyConnection proxy, Action<int, bool> count, CancellationToken token)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        // Cache both streams before either direction can half-close a socket.
        // TcpClient.GetStream() may reject calls after Shutdown(Send), even while
        // its existing NetworkStream remains readable.
        var clientStream = client.GetStream(); var proxyStream = proxy.Stream;
        async Task Pump(NetworkStream input, NetworkStream output, Socket outputSocket, bool upload)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(65536);
            try
            {
                while (true)
                {
                    var length = await input.ReadAsync(buffer, stop.Token);
                    if (length == 0) { outputSocket.Shutdown(SocketShutdown.Send); break; }
                    await output.WriteAsync(buffer.AsMemory(0, length), stop.Token); count(length, upload);
                }
            }
            catch { stop.Cancel(); throw; }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
        }
        await Task.WhenAll(Pump(clientStream, proxyStream, proxy.Client.Client, true), Pump(proxyStream, clientStream, client.Client, false));
    }
}
