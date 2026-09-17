using System.Net;
using System.Net.Sockets;

namespace ProxyWin.Core;

public sealed class CapturePlan
{
    public sealed record Network(IPAddress Start, IPAddress End, int Prefix)
    {
        public bool Contains(IPAddress address)
        {
            if (address.AddressFamily != Start.AddressFamily) return false;
            var bytes = address.GetAddressBytes();
            return bytes.AsSpan().SequenceCompareTo(Start.GetAddressBytes()) >= 0 && bytes.AsSpan().SequenceCompareTo(End.GetAddressBytes()) <= 0;
        }
        public string Filter => $"({(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")} and {(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")}.DstAddr >= {Start} and {(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")}.DstAddr <= {End})";
    }
    public sealed record Entry(RoutingRule Rule, ProxyServer? Proxy, Network[] Networks, (int Start, int End)[] Ports)
    {
        public RuleAction Action => Rule.Action;
        public bool Matches(IPAddress ip, int port, bool udp) => (Networks.Length == 0 || Networks.Any(n => n.Contains(ip)))
            && (Ports.Length == 0 || Ports.Any(p => port >= p.Start && port <= p.End))
            && (Rule.Network == Transport.Both || (udp ? Rule.Network == Transport.Udp : Rule.Network == Transport.Tcp));
    }
    public Entry[] Entries { get; }
    public bool NeedsProcessLookup => Entries.Any(e => e.Rule.ProcessName.Length > 0);

    public CapturePlan(Profile profile)
    {
        RuleParser.Validate(profile);
        Entries = profile.Rules.Where(r => r.Enabled).Select(rule =>
        {
            var networks = ParseNetworks(rule.Destinations);
            if (networks.Any(n => IPAddress.IsLoopback(n.Start) && IPAddress.IsLoopback(n.End)))
                throw new FormatException($"'{rule.Name}': loopback destinations are not supported.");
            return new Entry(rule with { }, rule.Action == RuleAction.Proxy && profile.Proxies.FirstOrDefault(p => p.Id == rule.ProxyId) is { } proxy ? proxy with { } : null,
                networks, RuleParser.Ports(rule.Ports));
        }).ToArray();
        if (Entries.Length == 0) throw new FormatException("Enable at least one rule.");
    }

    public Entry? Match(IPAddress destination, int port, bool udp, string? processName = null) => Entries.FirstOrDefault(e =>
        e.Matches(destination, port, udp) && (e.Rule.ProcessName.Length == 0 ||
        string.Equals(e.Rule.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? e.Rule.ProcessName[..^4] : e.Rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase)));

    public string Filter(int tcpPort4, int tcpPort6)
    {
        var captured = Entries.Where(e => e.Action != RuleAction.Direct).ToArray();
        if (captured.Length == 0) return "false";
        var selections = captured.Select(e =>
        {
            var addresses = e.Networks.Length == 0 ? "ip or ipv6" : string.Join(" or ", e.Networks.Select(n => n.Filter));
            string PortFilter(string protocol) => e.Ports.Length == 0 ? protocol :
                $"({protocol} and ({string.Join(" or ", e.Ports.Select(p => $"({protocol}.DstPort >= {p.Start} and {protocol}.DstPort <= {p.End})"))}))";
            var protocols = e.Rule.Network switch { Transport.Tcp => PortFilter("tcp"), Transport.Udp => PortFilter("udp"), _ => $"({PortFilter("tcp")} or {PortFilter("udp")})" };
            return $"(({addresses}) and ({protocols} or fragment))";
        });
        // Replies from our TCP listeners also need reverse translation. Destination *
        // broadens capture; executable-name matching happens after capture.
        var replies = Entries.Any(e => e.Action == RuleAction.Proxy && e.Rule.Network != Transport.Udp)
            ? $"(tcp and (tcp.SrcPort == {tcpPort4} or tcp.SrcPort == {tcpPort6}))" : "false";
        return $"outbound and !loopback and ({replies} or ({string.Join(" or ", selections)}))";
    }

    public static Network[] ParseNetworks(string value) => RuleParser.Networks(value).Select(cidr =>
    {
        var parts = cidr.Split('/'); var first = IPAddress.Parse(parts[0]); var prefix = int.Parse(parts[1]);
        var bytes = first.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++) bytes[i] |= (byte)(0xff >> Math.Clamp(prefix - i * 8, 0, 8));
        return new Network(first, new IPAddress(bytes), prefix);
    }).ToArray();
}
