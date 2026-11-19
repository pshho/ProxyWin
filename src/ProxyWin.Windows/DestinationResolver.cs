using System.Globalization;
using System.Net;
using System.Net.Sockets;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public static class DestinationResolver
{
    public static Task<string> ResolveAsync(string value, CancellationToken cancellationToken = default) =>
        ResolveAsync(value, Dns.GetHostAddressesAsync, cancellationToken);

    internal static async Task<string> ResolveAsync(string value,
        Func<string, CancellationToken, Task<IPAddress[]>> lookup, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (value.Trim() == "*") return "*";
        var tokens = value.Split(',', StringSplitOptions.TrimEntries);
        var hosts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // Validate the complete input before issuing any DNS requests.
        foreach (var token in tokens)
        {
            if (IPAddress.TryParse(token, out _) || token.Contains('/') || token.Contains(':'))
            {
                RuleParser.Networks(token);
                continue;
            }
            string host;
            try { host = new IdnMapping().GetAscii(token.EndsWith('.') ? token[..^1] : token); }
            catch (ArgumentException) { throw new FormatException($"대상 '{token}'이(가) 올바르지 않습니다. IP, CIDR, 도메인(예: example.com)만 입력하세요. http://나 경로·포트는 빼야 하며, 모든 대상은 * 하나만 입력합니다."); }
            if (host.Length is 0 or > 253 || host.All(c => char.IsAsciiDigit(c) || c == '.')
                || host.Split('.').Any(label => label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-'
                    || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
                throw new FormatException($"대상 '{token}'이(가) 올바르지 않습니다. IP, CIDR, 도메인(예: example.com)만 입력하세요. http://나 경로·포트는 빼야 하며, 모든 대상은 * 하나만 입력합니다.");
            hosts[token] = host;
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var resolved = new Dictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase);
        var output = new List<string>();
        var networks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in tokens)
        {
            if (!hosts.TryGetValue(token, out var host)) { Add(token); continue; }
            if (!resolved.TryGetValue(host, out var addresses))
            {
                try { addresses = await lookup(host, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false); }
                catch (SocketException) { throw new FormatException($"'{token}'의 IP를 찾을 수 없습니다. 도메인 철자와 DNS(인터넷) 연결을 확인하세요."); }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                { throw new FormatException($"'{token}' DNS 조회 시간이 초과되었습니다. 다시 시도하세요."); }
                addresses = addresses.Where(a => (a.AddressFamily == AddressFamily.InterNetwork
                    || a.AddressFamily == AddressFamily.InterNetworkV6 && a.ScopeId == 0) && !a.IsIPv4MappedToIPv6).Distinct().ToArray();
                if (addresses.Length == 0) throw new FormatException($"'{token}'에 사용할 수 있는 IPv4/IPv6 주소가 없습니다.");
                resolved[host] = addresses;
            }
            foreach (var address in addresses) Add(address.ToString());
        }
        return string.Join(", ", output);

        void Add(string address)
        {
            if (networks.Add(RuleParser.Networks(address).Single())) output.Add(address);
        }
    }
}
