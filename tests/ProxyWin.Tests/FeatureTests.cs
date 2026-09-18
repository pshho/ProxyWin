using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using ProxyWin.Windows;

internal static class FeatureTests
{
    private static void Check(bool condition) { if (!condition) throw new Exception("Feature assertion failed."); }
    public static async Task Destinations()
    {
        var calls = 0;
        Task<IPAddress[]> Lookup(string host, CancellationToken token)
        {
            calls++;
            Check(host is "example.com" or "xn--bcher-kva.example");
            return Task.FromResult(new[] { IPAddress.Parse("203.0.113.10"), IPAddress.Parse("2001:db8::1"), IPAddress.Parse("203.0.113.10") });
        }
        var result = await DestinationResolver.ResolveAsync("example.com, EXAMPLE.com., 203.0.113.10, 10.0.0.0/8", Lookup);
        Check(result == "203.0.113.10, 2001:db8::1, 10.0.0.0/8" && calls == 1);
        Check(await DestinationResolver.ResolveAsync("bücher.example", Lookup) == "203.0.113.10, 2001:db8::1");
        calls = 0;
        Check(await DestinationResolver.ResolveAsync("*", Lookup) == "*" && calls == 0);
        Check(await DestinationResolver.ResolveAsync("192.168.1.5/24, ::1", Lookup) == "192.168.1.5/24, ::1" && calls == 0);
        foreach (var input in new[] { "", "example.com,", "example.com,*", "https://example.com", "example.com:443", "127.1", "010.0.0.1", "192.168.*.*", "example.com/24", "fe80::1%2", "-bad.example", "a..com", "example.com.." })
        {
            try { await DestinationResolver.ResolveAsync(input, Lookup); throw new Exception("Accepted invalid destination: " + input); }
            catch (FormatException) { }
        }
        Check(calls == 0);
        try { await DestinationResolver.ResolveAsync("missing.example", (_, _) => throw new SocketException((int)SocketError.HostNotFound)); throw new Exception("Missing DNS accepted"); }
        catch (FormatException) { }
        try { await DestinationResolver.ResolveAsync("empty.example", (_, _) => Task.FromResult(Array.Empty<IPAddress>())); throw new Exception("Empty DNS accepted"); }
        catch (FormatException) { }
        using var cancellation = new CancellationTokenSource();
        var pending = DestinationResolver.ResolveAsync("slow.example", async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); return []; }, cancellation.Token);
        cancellation.Cancel();
        try { await pending; throw new Exception("Cancellation ignored"); } catch (OperationCanceledException) { }
    }

    public static async Task Updates()
    {
        Check(UpdateChecker.DescribeFailure(new HttpRequestException(HttpRequestError.SecureConnectionError, "SECRET_PROXY_PASSWORD")).Contains("TLS"));
        Check(!UpdateChecker.DescribeFailure(new HttpRequestException(HttpRequestError.SecureConnectionError, "SECRET_PROXY_PASSWORD")).Contains("SECRET"));
        Check(UpdateChecker.DescribeFailure(new HttpRequestException(HttpRequestError.NameResolutionError)).Contains("DNS"));
        Check(UpdateChecker.DescribeFailure(new HttpRequestException("SECRET", null, HttpStatusCode.Forbidden)).Contains("403"));
        Check(!UpdateChecker.DescribeFailure(new HttpRequestException("SECRET", null, HttpStatusCode.Forbidden)).Contains("SECRET"));
        Check(UpdateChecker.DescribeFailure(new TaskCanceledException()).Contains("timed out"));
        string Release(string version, string extra = "") => $$"""{"tag_name":"{{version}}","draft":false,"prerelease":false{{extra}}} """;
        var current = new Version(0, 5, 9, 0);
        Check(UpdateChecker.Parse(Release("v0.5.10"), current)?.Version == new Version(0, 5, 10));
        Check(UpdateChecker.Parse(Release("v0.5.9"), current) is null);
        Check(UpdateChecker.Parse(Release("v0.4.99"), current) is null);
        Check(UpdateChecker.Parse(Release("v1.0.0").Replace("\"prerelease\":false", "\"prerelease\":true"), current) is null);
        Check(UpdateChecker.Parse(Release("v1.0.0").Replace("\"draft\":false", "\"draft\":true"), current) is null);
        foreach (var tag in new[] { "v1.2", "v01.2.3", "v1.2.3-beta", "v1.2.3/evil", "v99999999999.0.0" })
        {
            try { UpdateChecker.Parse(Release(tag), current); throw new Exception("Accepted invalid tag"); } catch (FormatException) { }
        }
        Check(UpdateChecker.Parse(Release("v1.0.0", ",\"html_url\":\"https://untrusted.example\""), current)?.ReleasePage.AbsoluteUri == "https://github.com/pshho/ProxyWin/releases/tag/v1.0.0");
        using var client = new HttpClient(new Handler(request =>
        {
            Check(request.RequestUri?.AbsoluteUri == "https://api.github.com/repos/pshho/ProxyWin/releases/latest");
            Check(request.Headers.UserAgent.ToString() == "ProxyWin/0.5.9");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Release("v0.6.0")) };
        }));
        Check((await UpdateChecker.CheckAsync(client, current))?.Version == new Version(0, 6, 0));
        using var unavailable = new HttpClient(new Handler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        try { await UpdateChecker.CheckAsync(unavailable, current); throw new Exception("HTTP failure ignored"); } catch (HttpRequestException) { }
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }
}
