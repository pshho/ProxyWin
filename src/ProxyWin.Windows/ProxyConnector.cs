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
    // IPv4/IPv6 포트 공간은 서로 독립이므로 주소 계열까지 키에 넣어야
    // 다른 계열의 앱 소켓이 같은 번호를 써도 규칙을 우회하지 않는다.
    private readonly ConcurrentDictionary<(bool Udp, bool V6, int Port), long> ports = new();
    private long generation;
    internal int Count => ports.Count;
    public bool Contains(bool udp, int port) => Contains(udp, false, port) || Contains(udp, true, port);
    public bool Contains(bool udp, bool v6, int port) => ports.ContainsKey((udp, v6, port));
    public bool Contains(bool udp, AddressFamily family, int port) => Contains(udp, family == AddressFamily.InterNetworkV6, port);
    // 계열을 지정하지 않으면 듀얼모드 소켓으로 보고 양쪽 계열 모두 등록한다.
    public IDisposable Register(bool udp, int port) => Register(udp, [false, true], port);
    public IDisposable Register(bool udp, AddressFamily family, int port) => Register(udp, [family == AddressFamily.InterNetworkV6], port);
    private Registration Register(bool udp, bool[] families, int port)
    {
        var id = Interlocked.Increment(ref generation);
        var keys = families.Select(v6 => (udp, v6, port)).ToArray();
        foreach (var key in keys) ports[key] = id;
        return new Registration(() =>
        {
            foreach (var key in keys) ((ICollection<KeyValuePair<(bool Udp, bool V6, int Port), long>>)ports).Remove(new(key, id));
        });
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
        IDisposable lease;
        try
        {
            // 포트 고갈 등으로 Bind가 실패해도 소켓 핸들을 GC에 맡기지 않고 즉시 해제한다.
            client.Client.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
            lease = bypass.Register(false, server.AddressFamily, ((IPEndPoint)client.Client.LocalEndPoint!).Port);
        }
        catch { client.Dispose(); throw; }
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
                while (true)
                {
                    var start = count; var complete = false;
                    while (count < header.Length)
                    {
                        await connection.Stream.ReadExactlyAsync(header.AsMemory(count, 1), timeout.Token); count++;
                        if (count - start >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) { complete = true; break; }
                    }
                    var firstLine = Encoding.ASCII.GetString(header, start, count - start).Split("\r\n")[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (!complete || firstLine.Length < 2 || firstLine[0] is not ("HTTP/1.0" or "HTTP/1.1")
                        || firstLine[1].Length != 3 || !int.TryParse(firstLine[1], out var status) || status is < 100 or > 599)
                        throw new HttpConnectException(null);
                    // Interim responses precede the final reply. Keep one total header
                    // budget and timeout; 101 cannot establish a CONNECT tunnel.
                    if (status is >= 100 and < 200 && status != 101) continue;
                    if (status is < 200 or >= 300) throw new HttpConnectException(status);
                    break;
                }
            }
            return connection;
        }
        // Windows can surface cancellation as an aborted overlapped read instead
        // of OperationCanceledException. Preserve cancellation semantics without
        // classifying unrelated protocol or socket failures as cancellation.
        catch (IOException ex) when (timeout.IsCancellationRequested
            && ex.InnerException is SocketException { SocketErrorCode: SocketError.OperationAborted })
        {
            connection.Dispose();
            throw new OperationCanceledException("Proxy handshake was cancelled.", ex, timeout.Token);
        }
        catch (IOException ex) when (connected) { connection.Dispose(); throw new ProxyHandshakeException(proxy.Kind, ex); }
        catch { connection.Dispose(); throw; }
    }

    private static async Task AuthenticateAsync(NetworkStream stream, ProxyServer proxy, CancellationToken token)
    {
        var method = (byte)(proxy.Username.Length == 0 ? 0 : 2);
        await stream.WriteAsync(new byte[] { 5, 1, method }, token);
        var reply = new byte[2]; await stream.ReadExactlyAsync(reply, token);
        if (reply[0] != 5) throw new Socks5Exception("SOCKS5 응답이 아닙니다. 서버 종류(SOCKS5/HTTP)와 포트를 확인하세요.");
        if (reply[1] != method) throw new Socks5Exception(method == 0 ? "서버가 인증을 요구합니다. 사용자명/비밀번호를 입력하세요." : "서버가 사용자명/비밀번호 인증을 지원하지 않습니다.");
        if (method == 0) return;
        var username = Encoding.UTF8.GetBytes(proxy.Username); var password = Encoding.UTF8.GetBytes(proxy.Password);
        var auth = new byte[3 + username.Length + password.Length]; auth[0] = 1; auth[1] = (byte)username.Length;
        username.CopyTo(auth, 2); auth[2 + username.Length] = (byte)password.Length; password.CopyTo(auth, 3 + username.Length);
        try { await stream.WriteAsync(auth, token); }
        finally { Array.Clear(auth); Array.Clear(password); }
        await stream.ReadExactlyAsync(reply, token);
        if (reply[0] != 1 || reply[1] != 0) throw new Socks5Exception("사용자명 또는 비밀번호가 거부되었습니다.");
    }

    public static async Task<(string Host, int Port)> SocksCommandAsync(NetworkStream stream, byte command, IPEndPoint destination, CancellationToken token)
    {
        var address = EncodeAddress(destination);
        await stream.WriteAsync(new byte[] { 5, command, 0 }.Concat(address).ToArray(), token);
        var header = new byte[4]; await stream.ReadExactlyAsync(header, token);
        if (header[0] != 5 || header[2] != 0) throw new Socks5Exception("SOCKS5 응답 형식이 올바르지 않습니다. 서버 종류와 포트를 확인하세요.");
        if (header[1] != 0) throw new Socks5Exception(Socks5Exception.Reply(header[1]));
        string host;
        if (header[3] is 1 or 4)
        {
            var bytes = new byte[header[3] == 1 ? 4 : 16]; await stream.ReadExactlyAsync(bytes, token);
            host = new IPAddress(bytes).ToString();
        }
        else if (header[3] == 3)
        {
            var length = new byte[1]; await stream.ReadExactlyAsync(length, token);
            if (length[0] == 0) throw new Socks5Exception("SOCKS5 서버가 빈 중계 주소를 보냈습니다.");
            var bytes = new byte[length[0]]; await stream.ReadExactlyAsync(bytes, token); host = Encoding.ASCII.GetString(bytes);
        }
        else throw new Socks5Exception("SOCKS5 서버가 알 수 없는 주소 형식을 보냈습니다.");
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
