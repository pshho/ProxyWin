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
        if (string.IsNullOrWhiteSpace(value)) throw new FormatException("대상을 입력하세요. 예: 203.0.113.10, example.com — 모든 대상은 * 입력");
        var result = new List<string>();
        foreach (var token in Tokens(value))
        {
            var parts = token.Split('/');
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address)
                || parts[0].Contains('%') || address.IsIPv4MappedToIPv6
                || (address.AddressFamily == AddressFamily.InterNetwork && (parts[0].Split('.').Length != 4
                    || parts[0].Split('.').Any(part => !byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _) || (part.Length > 1 && part[0] == '0')))))
                throw new FormatException($"대상 '{token}'을(를) 이해할 수 없습니다. IP(203.0.113.10), CIDR(10.0.0.0/8), 도메인 또는 * 하나만 입력하고 여러 개는 쉼표로 구분하세요. 192.168.*.* 같은 부분 와일드카드는 CIDR(192.168.0.0/16)로 바꾸세요.");
            var max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            var prefix = max;
            if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > max))
                throw new FormatException($"CIDR 접두사는 0–{max} 사이여야 합니다.");
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
        if (string.IsNullOrWhiteSpace(value)) throw new FormatException("포트를 입력하세요. 예: 443 또는 80, 443 — 모든 포트는 * 입력");
        var result = new List<(int, int)>();
        foreach (var token in Tokens(value))
        {
            var pair = token.Split('-');
            if (pair.Length > 2 || !int.TryParse(pair[0], out var start) || start is < 1 or > 65535)
                throw new FormatException("포트는 1–65535 숫자나 범위를 쉼표로 구분해 입력하세요(예: 80, 443, 8000-9000). 모든 포트는 * 하나만 입력합니다.");
            var end = start;
            if (pair.Length == 2 && (!int.TryParse(pair[1], out end) || end < start || end > 65535))
                throw new FormatException("포트 범위가 올바르지 않습니다. 시작-끝 순서로 입력하세요(예: 8000-9000).");
            result.Add((start, end));
        }
        return result.Distinct().ToArray();
    }

    public static void Validate(Profile profile)
    {
        if (profile.Version is not (1 or 2)) throw new FormatException("지원하지 않는 설정 파일 버전입니다.");
        if (profile.Proxies is null || profile.Rules is null) throw new FormatException("설정 파일에 서버/규칙 목록이 없습니다.");
        var ids = new HashSet<string>(StringComparer.Ordinal) { "direct", "block" };
        foreach (var proxy in profile.Proxies)
        {
            if (proxy is null || string.IsNullOrWhiteSpace(proxy.Id) || !ids.Add(proxy.Id))
                throw new FormatException("프록시 서버 ID가 없거나 중복되었습니다.");
            if (string.IsNullOrWhiteSpace(proxy.Name) || !Enum.IsDefined(proxy.Kind))
                throw new FormatException("프록시 서버 이름과 종류를 확인하세요.");
            if (string.IsNullOrWhiteSpace(proxy.Host) || proxy.Host.Any(char.IsWhiteSpace)
                || proxy.Host.Contains('%') || Uri.CheckHostName(proxy.Host) == UriHostNameType.Unknown)
                throw new FormatException($"'{proxy.Name}': 호스트에 서버 IP 또는 도메인을 입력하세요(예: 127.0.0.1). http:// 같은 주소 형식은 빼고 입력합니다.");
            if (proxy.Port is < 1 or > 65535) throw new FormatException($"'{proxy.Name}': 포트는 1–65535 사이 숫자여야 합니다.");
            if (proxy.Username is null || proxy.Password is null) throw new FormatException("인증 정보가 올바르지 않습니다.");
            if (proxy.Username.Length == 0 && proxy.Password.Length > 0)
                throw new FormatException($"'{proxy.Name}': 비밀번호를 쓰려면 사용자명도 입력하세요.");
            if (proxy.Kind == ProxyKind.Socks5 && (System.Text.Encoding.UTF8.GetByteCount(proxy.Username) > 255
                || System.Text.Encoding.UTF8.GetByteCount(proxy.Password) > 255))
                throw new FormatException("SOCKS5 사용자명과 비밀번호는 각각 UTF-8 기준 255바이트 이하여야 합니다.");
        }
        foreach (var rule in profile.Rules)
        {
            if (rule is null || string.IsNullOrWhiteSpace(rule.Name) || !Enum.IsDefined(rule.Network) || !Enum.IsDefined(rule.Action))
                throw new FormatException("규칙의 동작과 프로토콜을 확인하세요.");
            if (rule.Destinations is null || rule.Ports is null) throw new FormatException("대상과 포트를 입력하세요.");
            if (rule.ProcessName is null || rule.ProcessName.IndexOfAny(['/', '\\', '*', '?']) >= 0)
                throw new FormatException("프로세스에는 실행 파일 이름만 입력하세요(예: chrome.exe). 경로나 * ? 와일드카드는 쓸 수 없습니다.");
            Networks(rule.Destinations);
            Ports(rule.Ports);
            var target = rule.Action == RuleAction.Proxy ? profile.Proxies.FirstOrDefault(p => p.Id == rule.ProxyId) : null;
            if (rule.Action == RuleAction.Proxy && target is null) throw new FormatException($"'{rule.Name}': PROXY 동작에는 프록시 서버가 필요합니다. 먼저 ① 프록시 서버를 추가/선택하세요.");
            if (rule.Action == RuleAction.Proxy && rule.Network != Transport.Tcp && target?.Kind == ProxyKind.Http)
                throw new FormatException($"'{rule.Name}': HTTP 프록시(Burp 등)는 TCP만 지원합니다. 프로토콜을 TCP로 바꾸거나 SOCKS5 서버를 사용하세요.");
        }
    }
}
