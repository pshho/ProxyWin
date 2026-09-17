using System.Net;

namespace ProxyWin.Core;

// Connection metadata only: never contains packet bodies or authentication data.
public sealed record ObservedConnection(DateTimeOffset Time, int ProcessId, string? ProcessName,
    IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, Transport Network, bool Loopback)
{
    public string TimeLabel => Time.ToLocalTime().ToString("HH:mm:ss.fff");
    public string ProcessLabel => ProcessName ?? "Unavailable / exited";
    public string Destination => RemoteAddress.ToString();
    public string NetworkLabel => Network == Transport.Tcp ? "TCP" : "UDP";
    public string LocalEndpoint => new IPEndPoint(LocalAddress, LocalPort).ToString();
    public string ScopeLabel => Loopback ? "Local" : "Remote";
    public bool CanRoute => Network is Transport.Tcp or Transport.Udp && !Loopback && !IPAddress.IsLoopback(RemoteAddress) && !RemoteAddress.IsIPv6LinkLocal
        && !RemoteAddress.IsIPv6Multicast && !RemoteAddress.Equals(IPAddress.Any) && !RemoteAddress.Equals(IPAddress.IPv6Any)
        && !(RemoteAddress.GetAddressBytes().Length == 4 && RemoteAddress.GetAddressBytes()[0] >= 224)
        && RemotePort is > 0 and <= 65535;

    public RoutingRule CreateRule(string proxyId, bool onlyThisProgram, RuleAction action = RuleAction.Proxy)
    {
        if (!Enum.IsDefined(action)) throw new FormatException("Select a valid action.");
        if (!CanRoute) throw new FormatException("This destination can only be monitored.");
        if (onlyThisProgram && string.IsNullOrEmpty(ProcessName))
            throw new FormatException("Process name unavailable. Capture a new connection or clear 'This process'.");
        return new RoutingRule
        {
            Name = $"{ProcessName ?? "All"} → {RemoteAddress}:{RemotePort}", Destinations = Destination,
            Ports = RemotePort.ToString(), Network = Network, Action = action,
            ProxyId = action == RuleAction.Proxy ? proxyId : action == RuleAction.Direct ? "direct" : "block",
            ProcessName = onlyThisProgram ? ProcessName! : ""
        };
    }
}
