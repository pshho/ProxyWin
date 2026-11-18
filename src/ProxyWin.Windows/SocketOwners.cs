using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using ProxyWin.Core;

namespace ProxyWin.Windows;

// 로컬 프록시(예: 127.0.0.1의 Burp) 프로세스 PID 집합을 짧게 캐시한다.
// 새 흐름마다 TCP 테이블을 읽으면 단일 캡처 스레드가 막혀 WinDivert 큐가 넘친다.
internal sealed class LocalProxyOwnerCache(IPEndPoint[] endpoints)
{
    private const long Lifetime = 1000;
    private readonly object sync = new();
    private HashSet<int> owners = [];
    private long refreshed = long.MinValue / 2;
    public bool Configured => endpoints.Length > 0;
    public HashSet<int> Current()
    {
        if (endpoints.Length == 0) return owners;
        lock (sync)
        {
            var now = Environment.TickCount64;
            if (now - refreshed >= Lifetime) { owners = SocketOwners.LocalProxyListeners(endpoints); refreshed = now; }
            return owners;
        }
    }
}

internal static class SocketOwners
{
    internal sealed record Owner(IPAddress Local, int Port, IPAddress? Remote, int RemotePort, int Pid, bool Listening);
    public static int? Find(FlowKey key)
    {
        var ipv4 = key.LocalAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var matches = Match(Read(key.Udp, ipv4 ? 2 : 23), key);
        // 듀얼모드(IPv6) 소켓의 IPv4 통신이 IPv6 테이블에 ::ffff:a.b.c.d로만 보이는 경우를 대비해
        // IPv4 조회가 비었을 때만 IPv6 테이블을 IPv4로 정규화해 다시 찾는다.
        if (ipv4 && matches.Length == 0)
            matches = Match(Read(key.Udp, 23).Select(row => row with { Local = Normalize(row.Local), Remote = row.Remote is null ? null : Normalize(row.Remote) }), key);
        return matches.Length == 1 ? matches[0] : null;
    }
    private static int[] Match(IEnumerable<Owner> rows, FlowKey key) => rows
        .Where(row => row.Port == key.LocalPort && (row.Local.Equals(key.LocalAddress) || row.Local.Equals(IPAddress.Any) || row.Local.Equals(IPAddress.IPv6Any))
            && (key.Udp || (row.Remote!.Equals(key.RemoteAddress) && row.RemotePort == key.RemotePort)))
        .Select(row => row.Pid).Distinct().Take(2).ToArray();
    public static string? Name(int? pid)
    {
        if (pid is null) return null;
        try { using var process = Process.GetProcessById(pid.Value); return process.ProcessName; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return null; }
    }
    public static HashSet<int> LocalProxyOwners(IEnumerable<IPEndPoint> servers) => LocalProxyListeners(LocalEndpoints(servers));

    // 이 PC 주소에 있는 프록시 서버만 고른다. 인터페이스 열거 비용이 크므로 세션 시작 시 1회만 호출한다.
    public static IPEndPoint[] LocalEndpoints(IEnumerable<IPEndPoint> servers)
    {
        var local = NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
            .Concat([IPAddress.Loopback, IPAddress.IPv6Loopback]).ToHashSet();
        return servers.Where(s => IPAddress.IsLoopback(Normalize(s.Address)) || local.Contains(Normalize(s.Address))).ToArray();
    }

    public static HashSet<int> LocalProxyListeners(IPEndPoint[] endpoints) =>
        endpoints.Length == 0 ? [] : MatchLocalProxyOwners(Read(false, 2).Concat(Read(false, 23)), endpoints);

    internal static HashSet<int> MatchLocalProxyOwners(IEnumerable<Owner> rows, IEnumerable<IPEndPoint> endpoints)
    {
        var targets = endpoints.Select(endpoint => (Address: Normalize(endpoint.Address), endpoint.Port)).ToArray();
        return rows.Where(row => row.Listening && targets.Any(target => row.Port == target.Port && MatchesLocalAddress(row.Local, target.Address)))
            .Select(row => row.Pid).ToHashSet();
    }

    private static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool MatchesLocalAddress(IPAddress listener, IPAddress endpoint)
    {
        listener = Normalize(listener);
        return listener.Equals(endpoint) || listener.AddressFamily == endpoint.AddressFamily
            && (listener.Equals(IPAddress.Any) || listener.Equals(IPAddress.IPv6Any));
    }

    private static IEnumerable<Owner> Read(bool udp, int family)
    {
        uint size = 0;
        _ = udp ? GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, 1, 0) : GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);
        for (var attempt = 0; attempt < 2 && size is > 0 and < 16 * 1024 * 1024; attempt++)
        {
            var buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                var available = size;
                var result = udp ? GetExtendedUdpTable(buffer, ref size, false, family, 1, 0) : GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
                if (result == 122) continue;
                if (result != 0) yield break;
                var count = Marshal.ReadInt32(buffer); var rowSize = (udp, family) switch { (true, 2) => 12, (true, _) => 28, (false, 2) => 24, _ => 56 };
                if (count < 0 || 4L + (long)count * rowSize > available) yield break;
                var row = new byte[rowSize];
                for (var i = 0; i < count; i++)
                {
                    Marshal.Copy(buffer + 4 + i * rowSize, row, 0, rowSize);
                    if (family == 2)
                    {
                        var start = udp ? 0 : 4;
                        yield return new Owner(new IPAddress(row.AsSpan(start, 4)), BinaryPrimitives.ReadUInt16BigEndian(row.AsSpan(start + 4)),
                            udp ? null : new IPAddress(row.AsSpan(12, 4)), udp ? 0 : BinaryPrimitives.ReadUInt16BigEndian(row.AsSpan(16)),
                            BinaryPrimitives.ReadInt32LittleEndian(row.AsSpan(udp ? 8 : 20)), !udp && BinaryPrimitives.ReadInt32LittleEndian(row) == 2);
                    }
                    else yield return new Owner(new IPAddress(row.AsSpan(0, 16)), BinaryPrimitives.ReadUInt16BigEndian(row.AsSpan(20)),
                        udp ? null : new IPAddress(row.AsSpan(24, 16)), udp ? 0 : BinaryPrimitives.ReadUInt16BigEndian(row.AsSpan(44)),
                        BinaryPrimitives.ReadInt32LittleEndian(row.AsSpan(udp ? 24 : 52)), !udp && BinaryPrimitives.ReadInt32LittleEndian(row.AsSpan(48)) == 2);
                }
                yield break;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, bool order, int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size, bool order, int family, int tableClass, uint reserved);
}
