using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ProxyWin.Core;

public enum FragmentDecision { Pass, Block, Drop }

public sealed class CapturePlan
{
    public sealed record Network(IPAddress Start, IPAddress End, int Prefix)
    {
        // 경계 주소는 생성 시 한 번만 숫자로 바꿔 두고, 매칭 때는 검사 대상 주소만 변환한다.
        private readonly UInt128 low = ToNumber(Start), high = ToNumber(End);
        public bool Contains(IPAddress address)
        {
            if (address.AddressFamily != Start.AddressFamily) return false;
            var value = ToNumber(address);
            return value >= low && value <= high;
        }
        private static UInt128 ToNumber(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];
            address.TryWriteBytes(bytes, out var length);
            return length == 4 ? BinaryPrimitives.ReadUInt32BigEndian(bytes) : BinaryPrimitives.ReadUInt128BigEndian(bytes);
        }
        public string Filter => $"({(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")} and {(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")}.DstAddr >= {Start} and {(Start.AddressFamily == AddressFamily.InterNetwork ? "ip" : "ipv6")}.DstAddr <= {End})";
    }
    public sealed record Entry(RoutingRule Rule, ProxyServer? Proxy, Network[] Networks, (int Start, int End)[] Ports)
    {
        // 프로세스 이름 비교용 값(.exe 제거)은 규칙마다 고정이므로 미리 계산한다.
        public string Program { get; } = Rule.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? Rule.ProcessName[..^4] : Rule.ProcessName;
        public RuleAction Action => Rule.Action;
        public bool Matches(IPAddress ip, int port, bool udp)
        {
            if (!MatchesAddress(ip, udp)) return false;
            if (Ports.Length == 0) return true;
            foreach (var range in Ports) if (port >= range.Start && port <= range.End) return true;
            return false;
        }
        public bool MatchesAddress(IPAddress ip, bool udp)
        {
            if (Rule.Network != Transport.Both && (udp ? Rule.Network != Transport.Udp : Rule.Network != Transport.Tcp)) return false;
            if (Networks.Length == 0) return true;
            foreach (var network in Networks) if (network.Contains(ip)) return true;
            return false;
        }
        public bool MatchesProcess(string? processName) => Program.Length == 0 || string.Equals(Program, processName, StringComparison.OrdinalIgnoreCase);
        // 포트·프로세스 조건이 없으면 주소와 프로토콜만으로 일치 여부가 확정된다.
        public bool AddressOnly => Ports.Length == 0 && Program.Length == 0;
    }
    public Entry[] Entries { get; }
    // 세션 동안 규칙이 바뀌지 않으므로 생성 시 한 번만 계산한다(UDP 패킷마다 평가됨).
    public bool NeedsProcessLookup { get; }

    public CapturePlan(Profile profile)
    {
        RuleParser.Validate(profile);
        Entries = profile.Rules.Where(r => r.Enabled).Select(rule =>
        {
            var networks = ParseNetworks(rule.Destinations);
            if (networks.Any(n => IPAddress.IsLoopback(n.Start) && IPAddress.IsLoopback(n.End)))
                throw new FormatException($"'{rule.Name}': 루프백(127.0.0.1, ::1) 대상은 지원하지 않습니다.");
            return new Entry(rule with { }, rule.Action == RuleAction.Proxy && profile.Proxies.FirstOrDefault(p => p.Id == rule.ProxyId) is { } proxy ? proxy with { } : null,
                networks, RuleParser.Ports(rule.Ports));
        }).ToArray();
        if (Entries.Length == 0) throw new FormatException("사용(체크)된 규칙이 없습니다. 규칙을 하나 이상 추가하거나 체크하세요.");
        NeedsProcessLookup = Entries.Any(e => e.Program.Length > 0);
    }

    // 프로세스 조건을 빼고 처음 맞는 규칙의 위치. 엔진은 이 위치부터 Match를 이어서 탐색한다.
    public int FirstIndex(IPAddress destination, int port, bool udp)
    {
        for (var i = 0; i < Entries.Length; i++) if (Entries[i].Matches(destination, port, udp)) return i;
        return -1;
    }

    public Entry? Match(IPAddress destination, int port, bool udp, string? processName = null, int start = 0)
    {
        if (start < 0) return null;
        for (var i = start; i < Entries.Length; i++)
        {
            var entry = Entries[i];
            if (entry.Matches(destination, port, udp) && entry.MatchesProcess(processName)) return entry;
        }
        return null;
    }

    // IP 조각은 재조립하지 않으므로 포트·프로세스를 알 수 없다. 목적지와 프로토콜만으로
    // 판정이 확정되는 경우(일치 규칙 없음, 조건 없는 DIRECT/BLOCK/PROXY)만 그대로 따르고,
    // 앞선 규칙의 포트·프로세스 조건 때문에 결과가 모호할 때만 폐기한다.
    public FragmentDecision ClassifyFragment(IPAddress destination, byte protocol)
    {
        // IPv6 Fragment 헤더 뒤에 다른 확장 헤더가 오면 상위 프로토콜(TCP/UDP)을 알 수 없으므로 둘 다 가능하다고 본다.
        var unknownTransport = protocol is 0 or 43 or 51 or 60;
        if (protocol is not (6 or 17) && !unknownTransport) return FragmentDecision.Pass;
        foreach (var entry in Entries)
        {
            var matches = unknownTransport ? entry.MatchesAddress(destination, false) || entry.MatchesAddress(destination, true) : entry.MatchesAddress(destination, protocol == 17);
            if (!matches) continue;
            if (!entry.AddressOnly || (unknownTransport && entry.Rule.Network != Transport.Both))
            {
                // 조건부 DIRECT는 놓쳐도 뒤 규칙이 전부 DIRECT면 결과가 같으므로 계속 본다.
                if (entry.Action == RuleAction.Direct) continue;
                return FragmentDecision.Drop;
            }
            return entry.Action switch { RuleAction.Direct => FragmentDecision.Pass, RuleAction.Block => FragmentDecision.Block, _ => FragmentDecision.Drop };
        }
        return FragmentDecision.Pass;
    }

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
            ? $"(tcp and ((ip and tcp.SrcPort == {tcpPort4}) or (ipv6 and tcp.SrcPort == {tcpPort6})))" : "false";
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
