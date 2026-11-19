using System.Net;
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
}
