using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using ProxyWin.Core;

namespace ProxyWin.Windows;

internal static class SocketOwners
{
    internal sealed record Owner(IPAddress Local, int Port, IPAddress? Remote, int RemotePort, int Pid, bool Listening);
    public static int? Find(FlowKey key)
    {
        var matches = Read(key.Udp, key.LocalAddress.GetAddressBytes().Length == 4 ? 2 : 23)
            .Where(row => row.Port == key.LocalPort && (row.Local.Equals(key.LocalAddress) || row.Local.Equals(IPAddress.Any) || row.Local.Equals(IPAddress.IPv6Any))
                && (key.Udp || (row.Remote!.Equals(key.RemoteAddress) && row.RemotePort == key.RemotePort)))
            .Select(row => row.Pid).Distinct().Take(2).ToArray();
        return matches.Length == 1 ? matches[0] : null;
    }
    public static string? Name(int? pid)
    {
        if (pid is null) return null;
        try { using var process = Process.GetProcessById(pid.Value); return process.ProcessName; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return null; }
    }
    public static HashSet<int> LocalProxyOwners(IEnumerable<IPEndPoint> servers)
    {
        var local = NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
            .Concat([IPAddress.Loopback, IPAddress.IPv6Loopback]).ToHashSet();
        var ports = servers.Where(s => local.Contains(s.Address)).Select(s => s.Port).ToHashSet();
        if (ports.Count == 0) return [];
        return Read(false, 2).Concat(Read(false, 23)).Where(row => row.Listening && ports.Contains(row.Port)).Select(row => row.Pid).ToHashSet();
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
