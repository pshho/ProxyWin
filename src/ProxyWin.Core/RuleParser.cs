using System.Net;
using System.Net.Sockets;
using System.Globalization;

namespace ProxyWin.Core;

public static class RuleParser
{
    private static string[] Tokens(string value) => value.Split(',', StringSplitOptions.TrimEntries);

    public static string[] Networks(string value)
    {
        if (value.Trim() == "*") return [];
        var result = new List<string>();
        foreach (var token in Tokens(value))
        {
            var parts = token.Split('/');
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address)
                || parts[0].Contains('%') || address.IsIPv4MappedToIPv6
                || (address.AddressFamily == AddressFamily.InterNetwork && (parts[0].Split('.').Length != 4
                    || parts[0].Split('.').Any(part => !byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _) || (part.Length > 1 && part[0] == '0')))))
                throw new FormatException("Use an IP, CIDR or *. Separate addresses with commas.");
            var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            var prefix = max;
            if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > max))
                throw new FormatException($"CIDR prefix must be 0–{max}.");
            var bytes = address.GetAddressBytes();
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] &= (byte)(0xff << Math.Clamp(8 - (prefix - i * 8), 0, 8));
            result.Add($"{new IPAddress(bytes)}/{prefix}");
        }
        return result.Distinct().ToArray();
    }

    public static (int Start, int End)[] Ports(string value)
    {
        if (value.Trim() == "*") return [];
        var result = new List<(int, int)>();
        foreach (var token in Tokens(value))
        {
            var pair = token.Split('-');
            if (pair.Length > 2 || !int.TryParse(pair[0], out var start) || start is < 1 or > 65535)
                throw new FormatException("Use ports 1–65535 or ranges, separated by commas (80, 443, 8000-9000), or * alone.");
            var end = start;
            if (pair.Length == 2 && (!int.TryParse(pair[1], out end) || end < start || end > 65535))
                throw new FormatException("Invalid port range.");
            result.Add((start, end));
        }
        return result.Distinct().ToArray();
    }

    public static void Validate(Profile profile)
    {
        if (profile.Version is not (1 or 2)) throw new FormatException("Unsupported profile version.");
        if (profile.Proxies is null || profile.Rules is null) throw new FormatException("Profile lists are missing.");
        var ids = new HashSet<string>(StringComparer.Ordinal) { "direct", "block" };
        foreach (var proxy in profile.Proxies)
        {
            if (proxy is null || string.IsNullOrWhiteSpace(proxy.Id) || !ids.Add(proxy.Id))
                throw new FormatException("Proxy ID is missing or duplicated.");
            if (string.IsNullOrWhiteSpace(proxy.Name) || !Enum.IsDefined(proxy.Kind))
                throw new FormatException("Check the proxy name and type.");
            if (string.IsNullOrWhiteSpace(proxy.Host) || proxy.Host.Any(char.IsWhiteSpace)
                || proxy.Host.Contains('%') || Uri.CheckHostName(proxy.Host) == UriHostNameType.Unknown)
                throw new FormatException($"'{proxy.Name}': enter a server IP or hostname.");
            if (proxy.Port is < 1 or > 65535) throw new FormatException($"'{proxy.Name}': port must be 1–65535.");
            if (proxy.Username is null || proxy.Password is null) throw new FormatException("Invalid credentials.");
            if (proxy.Username.Length == 0 && proxy.Password.Length > 0)
                throw new FormatException($"'{proxy.Name}': enter a username with the password.");
            if (proxy.Kind == ProxyKind.Socks5 && (System.Text.Encoding.UTF8.GetByteCount(proxy.Username) > 255
                || System.Text.Encoding.UTF8.GetByteCount(proxy.Password) > 255))
                throw new FormatException("SOCKS5 username and password must each be at most 255 UTF-8 bytes.");
        }
        foreach (var rule in profile.Rules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Name) || !Enum.IsDefined(rule.Network) || !Enum.IsDefined(rule.Action))
                throw new FormatException("Check the rule name, action and protocol.");
            if (rule.Destinations is null || rule.Ports is null) throw new FormatException("Enter a destination and port.");
            if (rule.ProcessName is null || rule.ProcessName.IndexOfAny(['/', '\\', '*', '?']) >= 0)
                throw new FormatException("Use an executable name, such as chrome.exe. No paths or process wildcards.");
            Networks(rule.Destinations);
            Ports(rule.Ports);
            var target = rule.Action == RuleAction.Proxy ? profile.Proxies.FirstOrDefault(p => p.Id == rule.ProxyId) : null;
            if (rule.Action == RuleAction.Proxy && target is null) throw new FormatException($"'{rule.Name}': select a proxy server.");
            if (rule.Action == RuleAction.Proxy && rule.Network != Transport.Tcp && target?.Kind == ProxyKind.Http)
                throw new FormatException($"'{rule.Name}': HTTP proxies do not support UDP.");
        }
    }
}
