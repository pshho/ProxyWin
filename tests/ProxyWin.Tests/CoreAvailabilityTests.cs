using System.Net;
using System.Runtime.CompilerServices;
using ProxyWin.Core;
using ProxyWin.Windows;

internal static class CoreAvailabilityTests
{
    public static Task ProfilePathStability()
    {
        var originalDirectory = Directory.GetCurrentDirectory();
        var root = Path.Combine(Path.GetTempPath(), "ProxyWin-profile-path-" + Guid.NewGuid().ToString("N"));
        var first = Path.Combine(root, "first");
        var second = Path.Combine(root, "second");
        Directory.CreateDirectory(first);
        Directory.CreateDirectory(second);
        try
        {
            Directory.SetCurrentDirectory(first);
            var store = new ProfileStore("profile");
            store.Save(new Profile { Rules = [new RoutingRule
            {
                Name = "Retained rule", Destinations = "203.0.113.10", Ports = "443", Action = RuleAction.Block
            }] });

            Directory.SetCurrentDirectory(second);
            if (store.DirectoryPath != Path.Combine(first, "profile"))
                throw new Exception("Profile directory changed with the process working directory");
            var loaded = store.Load();
            if (loaded.Rules.Count != 1 || loaded.Rules[0].Name != "Retained rule")
                throw new Exception("Saved profile became unavailable after the process working directory changed");
            loaded.Rules[0].Name = "Updated rule";
            store.Save(loaded);
            var originalStore = new ProfileStore(Path.Combine(first, "profile"));
            if (originalStore.Load().Rules.Single().Name != "Updated rule" || Directory.Exists(Path.Combine(second, "profile")))
                throw new Exception("Saving after a working-directory change wrote the profile to a different location");
        }
        finally
        {
            Directory.SetCurrentDirectory(originalDirectory);
            Directory.Delete(root, recursive: true);
        }
        return Task.CompletedTask;
    }

    public static Task NetworkMatching()
    {
        var ipv4 = CapturePlan.ParseNetworks("192.168.10.0/23").Single();
        var ipv6 = CapturePlan.ParseNetworks("2001:db8:abcd:1200::/56").Single();
        foreach (var (network, address, expected) in new (CapturePlan.Network, string, bool)[]
        {
            (ipv4, "192.168.9.255", false), (ipv4, "192.168.10.0", true),
            (ipv4, "192.168.11.255", true), (ipv4, "192.168.12.0", false),
            (ipv4, "2001:db8:abcd:1200::", false),
            (ipv6, "2001:db8:abcd:11ff:ffff:ffff:ffff:ffff", false),
            (ipv6, "2001:db8:abcd:1200::", true),
            (ipv6, "2001:db8:abcd:12ff:ffff:ffff:ffff:ffff", true),
            (ipv6, "2001:db8:abcd:1300::", false), (ipv6, "192.168.10.0", false)
        })
        {
            if (network.Contains(IPAddress.Parse(address)) != expected)
                throw new Exception($"CIDR boundary match failed for {address}");
        }

        var ipv4Address = IPAddress.Parse("192.168.10.23");
        var ipv6Address = IPAddress.Parse("2001:db8:abcd:1234::5");
        const int samples = 20_000;
        // Warm the same optimized loop that is measured, rather than switching
        // from a separate warm-up loop into a tiered/OSR measurement loop.
        _ = MeasureMatches(ipv4, ipv6, ipv4Address, ipv6Address, samples);
        var (matches, allocated) = MeasureMatches(ipv4, ipv6, ipv4Address, ipv6Address, samples);
        Console.WriteLine($"  Network.Contains: {allocated} allocated bytes for {samples * 2} warmed calls");
        if (matches != samples * 2) throw new Exception("CIDR match changed during allocation measurement");
        if (allocated >= 4_096) throw new Exception($"Network.Contains allocated {allocated} bytes for warmed matches");
        return Task.CompletedTask;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    private static (int Matches, long Allocated) MeasureMatches(CapturePlan.Network ipv4, CapturePlan.Network ipv6,
        IPAddress ipv4Address, IPAddress ipv6Address, int samples)
    {
        var matches = 0;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < samples; i++)
        {
            if (ipv4.Contains(ipv4Address)) matches++;
            if (ipv6.Contains(ipv6Address)) matches++;
        }
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        return (matches, allocated);
    }
}
