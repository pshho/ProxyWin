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
            if (byVirtual.Count >= 16384) return null;
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
            if (flow is null || flow.Accepted || !flow.Key.RemoteAddress.Equals(peer.Address) || !flow.Key.LocalAddress.Equals(local.Address)) return null;
            flow.Accepted = true; return flow;
        }
    }
    public void Sweep()
    {
        var now = Environment.TickCount64;
        lock (sync)
        {
            foreach (var flow in byVirtual.Values.Where(f => (Volatile.Read(ref f.Closed) != 0 && now - Volatile.Read(ref f.Closed) > 120000)
                || (!f.Accepted && now - Volatile.Read(ref f.LastSeen) > 30000)).ToArray())
            {
                byVirtual.Remove(flow.VirtualPort);
                if (byOriginal.GetValueOrDefault(flow.Key) == flow) byOriginal.Remove(flow.Key);
            }
        }
    }
}
