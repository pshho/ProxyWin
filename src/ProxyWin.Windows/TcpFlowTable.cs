using System.Net;
using ProxyWin.Core;

namespace ProxyWin.Windows;

internal sealed class TcpFlow(FlowKey key, CapturePlan.Entry route, int virtualPort, uint sequence)
{
    public FlowKey Key { get; } = key;
    public CapturePlan.Entry Route { get; } = route;
    public int VirtualPort { get; } = virtualPort;
    public uint Sequence { get; } = sequence;
    public long LastSeen = Environment.TickCount64;
    public long Closed;
    public bool Accepted;
}

internal sealed class TcpFlowTable
{
    internal const int Capacity = 16384;
    private readonly object sync = new();
    private readonly Dictionary<FlowKey, TcpFlow> byOriginal = [];
    private readonly Dictionary<int, TcpFlow> byVirtual = [];
    private int cursor = 10000;
    public TcpFlow? Find(FlowKey key) { lock (sync) return byOriginal.GetValueOrDefault(key); }
    public TcpFlow? FindVirtual(int port) { lock (sync) return byVirtual.GetValueOrDefault(port); }
    public TcpFlow? Create(FlowKey key, CapturePlan.Entry route, uint sequence, int listener4, int listener6)
    {
        lock (sync)
        {
            if (byVirtual.Count >= Capacity && !ReclaimClosed()) return null;
            for (var attempt = 0; attempt < 55535; attempt++)
            {
                cursor = cursor == 65535 ? 10000 : cursor + 1;
                if (cursor == listener4 || cursor == listener6 || byVirtual.ContainsKey(cursor)) continue;
                var flow = new TcpFlow(key, route, cursor, sequence);
                byVirtual.Add(cursor, flow); byOriginal[key] = flow; return flow;
            }
            return null;
        }
    }
    public TcpFlow? Accept(IPEndPoint peer, IPEndPoint local)
    {
        lock (sync)
        {
            var flow = byVirtual.GetValueOrDefault(peer.Port);
            if (flow is null || flow.Accepted || !SameAddress(flow.Key.RemoteAddress, peer.Address) || !SameAddress(flow.Key.LocalAddress, local.Address)) return null;
            flow.Accepted = true; return flow;
        }
    }
    // 닫힌 흐름은 늦게 도착하는 FIN/ACK 변환을 위해 잠시 보관하지만, 짧은 연결이 몰려
    // 상한에 닿으면 새 SYN을 버리는 대신 가장 오래 닫혀 있던 흐름부터 1/8씩 회수한다.
    private bool ReclaimClosed()
    {
        var closed = byVirtual.Values.Where(f => Volatile.Read(ref f.Closed) != 0)
            .OrderBy(f => Volatile.Read(ref f.Closed)).Take(Capacity / 8).ToArray();
        foreach (var flow in closed) Remove(flow);
        return closed.Length > 0;
    }

    private void Remove(TcpFlow flow)
    {
        byVirtual.Remove(flow.VirtualPort);
        if (byOriginal.GetValueOrDefault(flow.Key) == flow) byOriginal.Remove(flow.Key);
    }

    // 패킷에서 만든 주소(ScopeId 0)와 accept된 소켓 주소(링크로컬이면 ScopeId 포함)를 바이트로만 비교한다.
    internal static bool SameAddress(IPAddress a, IPAddress b)
    {
        if (a.AddressFamily != b.AddressFamily) return false;
        Span<byte> left = stackalloc byte[16], right = stackalloc byte[16];
        a.TryWriteBytes(left, out var leftLength); b.TryWriteBytes(right, out var rightLength);
        return left[..leftLength].SequenceEqual(right[..rightLength]);
    }

    public void Sweep()
    {
        var now = Environment.TickCount64;
        lock (sync)
        {
            foreach (var flow in byVirtual.Values.Where(f => (Volatile.Read(ref f.Closed) != 0 && now - Volatile.Read(ref f.Closed) > 120000)
                || (!f.Accepted && now - Volatile.Read(ref f.LastSeen) > 30000)).ToArray())
                Remove(flow);
        }
    }
}
