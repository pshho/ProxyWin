using System.Net;

namespace ProxyWin.Core;

// Connection metadata only: never contains packet bodies or authentication data.
public sealed record ObservedConnection(DateTimeOffset Time, int ProcessId, string? ProcessName,
    IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, Transport Network, bool Loopback)
{
    public string TimeLabel => Time.ToLocalTime().ToString("HH:mm:ss.fff");
    public string ProcessLabel => ProcessName ?? "알 수 없음 / 종료됨";
    public string Destination => RemoteAddress.ToString();
    public string NetworkLabel => Network == Transport.Tcp ? "TCP" : "UDP";
    public string LocalEndpoint => new IPEndPoint(LocalAddress, LocalPort).ToString();
    public string ScopeLabel => Loopback ? "로컬" : "외부";
    public bool CanRoute => Network is Transport.Tcp or Transport.Udp && !Loopback && !IPAddress.IsLoopback(RemoteAddress) && !RemoteAddress.IsIPv6LinkLocal
        && !RemoteAddress.IsIPv6Multicast && !RemoteAddress.Equals(IPAddress.Any) && !RemoteAddress.Equals(IPAddress.IPv6Any)
        && !(RemoteAddress.GetAddressBytes().Length == 4 && RemoteAddress.GetAddressBytes()[0] >= 224)
        && RemotePort is > 0 and <= 65535;

    public RoutingRule CreateRule(string proxyId, bool onlyThisProgram, RuleAction action = RuleAction.Proxy)
    {
        if (!Enum.IsDefined(action)) throw new FormatException("올바른 동작을 선택하세요.");
        if (!CanRoute) throw new FormatException("이 대상(로컬·멀티캐스트·링크로컬)은 모니터링만 가능하고 규칙으로 보낼 수 없습니다.");
        if (onlyThisProgram && string.IsNullOrEmpty(ProcessName))
            throw new FormatException("프로세스 이름을 알 수 없습니다. 새 연결을 다시 잡거나 '이 프로세스만'을 해제하세요.");
        return new RoutingRule
        {
            Name = $"{ProcessName ?? "전체"} → {RemoteAddress}:{RemotePort}", Destinations = Destination,
            Ports = RemotePort.ToString(), Network = Network, Action = action,
            ProxyId = action == RuleAction.Proxy ? proxyId : action == RuleAction.Direct ? "direct" : "block",
            ProcessName = onlyThisProgram ? ProcessName! : ""
        };
    }
}
