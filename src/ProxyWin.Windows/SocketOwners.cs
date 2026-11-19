using System.Buffers.Binary;
using System.Collections.Concurrent;
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
        var matches = Match(Read(key.Udp, ipv4 ? 2 : 23, key.LocalPort), key);
        // 듀얼모드(IPv6) 소켓의 IPv4 통신이 IPv6 테이블에 ::ffff:a.b.c.d로만 보이는 경우를 대비해
        // IPv4 조회가 비었을 때만 IPv6 테이블을 IPv4로 정규화해 다시 찾는다.
        if (ipv4 && matches.Length == 0)
            matches = Match(Read(key.Udp, 23, key.LocalPort).Select(row => row with { Local = Normalize(row.Local), Remote = row.Remote is null ? null : Normalize(row.Remote) }), key);
        return matches.Length == 1 ? matches[0] : null;
    }
    private static int[] Match(IEnumerable<Owner> rows, FlowKey key) => rows
        .Where(row => row.Port == key.LocalPort && (row.Local.Equals(key.LocalAddress) || row.Local.Equals(IPAddress.Any) || row.Local.Equals(IPAddress.IPv6Any))
            && (key.Udp || (row.Remote!.Equals(key.RemoteAddress) && row.RemotePort == key.RemotePort)))
        .Select(row => row.Pid).Distinct().Take(2).ToArray();
    // 규칙 비교용 이름(.exe 제외). 캡처 스레드에서 불리므로 ProcessNames의 캐시된 직접 조회를 쓴다.
    public static string? Name(int? pid)
    {
        if (pid is null || ProcessNames.FileName(pid.Value) is not { } file) return null;
        return file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
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

    // port를 주면 포트가 다른 행은 객체를 만들기 전에 건너뛴다(새 흐름마다 수천 행을 할당하지 않도록).
    private static IEnumerable<Owner> Read(bool udp, int family, int port = -1)
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
                    if (port >= 0 && BinaryPrimitives.ReadUInt16BigEndian(row.AsSpan(family == 2 ? (udp ? 4 : 8) : 20)) != port) continue;
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

// 프로세스 이미지 이름 조회. Process.ProcessName은 시스템 전체 프로세스 목록을 모을 수 있어 비싸므로
// 프로세스 핸들로 경로만 직접 읽고, (PID, 생성 시각)으로 캐시해 PID 재사용을 구분한다.
internal static class ProcessNames
{
    private const uint QueryLimitedInformation = 0x1000;
    private static readonly ConcurrentDictionary<(int Pid, long Created), string> cache = new();

    // 실행 파일 이름(확장자 포함). notCreatedAfterUtc보다 나중에 생성된 프로세스(PID 재사용)면 null.
    public static string? FileName(int pid, DateTime? notCreatedAfterUtc = null)
    {
        var handle = OpenProcess(QueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero) return Fallback(pid, notCreatedAfterUtc);
        try
        {
            if (!GetProcessTimes(handle, out var created, out _, out _, out _)) return Fallback(pid, notCreatedAfterUtc);
            if (notCreatedAfterUtc is { } limit && DateTime.FromFileTimeUtc(created) > limit) return null;
            if (cache.TryGetValue((pid, created), out var cached)) return cached;
            var name = ImageName(handle);
            if (name is null) return Fallback(pid, notCreatedAfterUtc);
            if (cache.Count > 4096) cache.Clear();
            cache[(pid, created)] = name;
            return name;
        }
        finally { CloseHandle(handle); }
    }

    private static unsafe string? ImageName(IntPtr handle)
    {
        var buffer = stackalloc char[1024]; var size = 1024u;
        if (!QueryFullProcessImageNameW(handle, 0, buffer, ref size) || size == 0) return null;
        var path = new string(buffer, 0, (int)size);
        return Path.GetFileName(path);
    }

    // 보호 프로세스 등 직접 조회가 막힌 경우에만 기존 방식으로 대신한다.
    private static string? Fallback(int pid, DateTime? notCreatedAfterUtc)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            if (notCreatedAfterUtc is { } limit && process.StartTime.ToUniversalTime() > limit) return null;
            return process.ProcessName + ".exe";
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return null; }
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern unsafe bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* name, ref uint size);
}
