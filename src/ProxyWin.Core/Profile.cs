using System.Text.Json.Serialization;

namespace ProxyWin.Core;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ProxyKind { Socks5, Http }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Transport { Tcp, Udp, Both }
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RuleAction { Direct, Proxy, Block }

public sealed record ProxyServer
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "New proxy";
    public ProxyKind Kind { get; set; } = ProxyKind.Socks5;
    public string Host { get; set; } = "";
    public int Port { get; set; } = 1080;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    [JsonIgnore] public string Endpoint => Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
    [JsonIgnore] public string ProtocolLabel => Kind == ProxyKind.Socks5 ? "SOCKS5 · TCP/UDP" : "HTTP · TCP";
    [JsonIgnore] public string Summary => $"{Name} · {Endpoint} · {(Kind == ProxyKind.Socks5 ? "SOCKS5" : "HTTP")}";
}

public sealed record RoutingRule
{
    private RuleAction? action;
    public string Name { get; set; } = "New rule";
    public bool Enabled { get; set; } = true;
    public string Destinations { get; set; } = "";
    public string Ports { get; set; } = "*";
    public Transport Network { get; set; } = Transport.Tcp;
    public string ProxyId { get; set; } = "direct";
    // Version-1 profiles omitted Action and used the "direct" target sentinel.
    public RuleAction Action { get => action ?? (ProxyId == "direct" ? RuleAction.Direct : RuleAction.Proxy); set => action = value; }
    public string ProcessName { get; set; } = "";
    [JsonIgnore] public string ActionLabel => Action.ToString().ToUpperInvariant();
    [JsonIgnore] public string NetworkLabel => Network switch { Transport.Tcp => "TCP", Transport.Udp => "UDP", _ => "TCP + UDP" };
}

public sealed class Profile
{
    public int Version { get; set; } = 2;
    public List<ProxyServer> Proxies { get; set; } = [];
    public List<RoutingRule> Rules { get; set; } = [];
}
