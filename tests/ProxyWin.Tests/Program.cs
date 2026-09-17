using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using ProxyWin.Core;
using ProxyWin.Windows;

var reportIndex = Array.IndexOf(args, "--report");
if (reportIndex >= 0 && reportIndex + 1 < args.Length)
{
    var reportPath = Path.GetFullPath(args[reportIndex + 1]); Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
    var writer = new StreamWriter(reportPath, append: false, Encoding.UTF8) { AutoFlush = true };
    Console.SetOut(writer); Console.SetError(writer);
}

var gatedClient = args.Length == 7 && args[^1] == "--wait-start";
var clientArgs = gatedClient ? args[..^1] : args;
if (clientArgs is ["--client", var protocol, var ip, var portText, var expected, var countText])
{
    try
    {
        if (gatedClient && Console.ReadLine() != "start") throw new InvalidOperationException("Missing test start signal");
        await Task.WhenAll(Enumerable.Range(0, int.Parse(countText)).Select(async _ =>
        {
            // Bulk is a throughput measurement, not a minimum-speed assertion.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(protocol == "bulk" ? 30 : 12));
            var endpoint = new IPEndPoint(IPAddress.Parse(ip), int.Parse(portText));
            if (protocol is "block-tcp" or "block-udp")
            {
                using var blockedTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(700));
                var prevented = false;
                try
                {
                    if (protocol == "block-tcp")
                    {
                        using var blocked = new TcpClient(endpoint.AddressFamily);
                        await blocked.ConnectAsync(endpoint.Address, endpoint.Port, blockedTimeout.Token);
                    }
                    else
                    {
                        using var blocked = new UdpClient(endpoint.AddressFamily); blocked.Connect(endpoint);
                        await blocked.SendAsync("ping"u8.ToArray(), blockedTimeout.Token);
                        await blocked.ReceiveAsync(blockedTimeout.Token);
                    }
                }
                catch (OperationCanceledException) { prevented = true; }
                if (!prevented) throw new Exception("Blocked test unexpectedly connected or received a reply");
            }
            else if (protocol == "bulk")
            {
                const int total = 32 * 1024 * 1024;
                using var client = new TcpClient(endpoint.AddressFamily) { NoDelay = true };
                await client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
                var stream = client.GetStream();
                var clock = Stopwatch.StartNew();
                var sentCount = 0; var receivedCount = 0;
                async Task Send()
                {
                    var data = new byte[65536]; Array.Fill(data, (byte)0x5a);
                    for (var n = 0; n < total; n += data.Length) { await stream.WriteAsync(data, timeout.Token); Interlocked.Add(ref sentCount, data.Length); }
                    client.Client.Shutdown(SocketShutdown.Send);
                }
                async Task Receive()
                {
                    var data = new byte[65536]; var received = 0; int length;
                    while ((length = await stream.ReadAsync(data, timeout.Token)) != 0)
                    {
                        if (data.AsSpan(0, length).IndexOfAnyExcept((byte)0x5a) >= 0) throw new Exception("Bulk corruption");
                        received += length;
                        Interlocked.Add(ref receivedCount, length);
                    }
                    if (received != total) throw new Exception("Bulk size mismatch");
                }
                try { await Task.WhenAll(Send(), Receive()); }
                finally { Console.WriteLine($"Bulk progress: sent={sentCount}, received={receivedCount}, elapsed={clock.Elapsed.TotalSeconds:F3}s"); }
                clock.Stop();
                Console.WriteLine($"BENCH 32 MiB upload + verified echo: {clock.Elapsed.TotalSeconds:F3} s; one-way payload rate {total * 8 / clock.Elapsed.TotalSeconds / 1000000:F1} Mbit/s (local test, not WAN)");
            }
            else if (protocol == "tcp")
            {
                using var client = new TcpClient(endpoint.AddressFamily) { NoDelay = true };
                await client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
                await client.GetStream().WriteAsync("ping"u8.ToArray(), timeout.Token);
                using var output = new MemoryStream(); await client.GetStream().CopyToAsync(output, timeout.Token);
                if (Encoding.ASCII.GetString(output.ToArray()) != expected) throw new Exception("TCP reply mismatch");
            }
            else
            {
                using var udp = new UdpClient(endpoint.AddressFamily); udp.Connect(endpoint);
                await udp.SendAsync("ping"u8.ToArray(), timeout.Token);
                var reply = await udp.ReceiveAsync(timeout.Token);
                if (Encoding.ASCII.GetString(reply.Buffer) != expected || !reply.RemoteEndPoint.Equals(endpoint)) throw new Exception("UDP original source or payload mismatch");
            }
        }));
        return 0;
    }
    catch (Exception ex) { Console.WriteLine(ex.ToString()); return 1; }
}

var failures = 0; var tests = 0;
using var watchdog = args.Contains("--driver") ? new Timer(_ => { Console.WriteLine("FAIL driver test watchdog expired; terminating the test host to release all driver handles."); Environment.Exit(124); }, null, TimeSpan.FromSeconds(60), Timeout.InfiniteTimeSpan) : null;
void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
void Reject(Action action) { try { action(); } catch (FormatException) { return; } throw new Exception("Expected validation rejection"); }
async Task Test(string name, Func<Task> action)
{
    tests++;
    try { await action(); Console.WriteLine("PASS " + name); }
    catch (Exception ex) { failures++; Console.WriteLine("FAIL " + name + ": " + ex); }
}
Task Sync(Action action) { action(); return Task.CompletedTask; }
Profile Example() => new()
{
    Proxies = [new ProxyServer { Id = "s", Host = "127.0.0.1" }],
    Rules = [new RoutingRule { Destinations = "203.0.113.10", ProxyId = "s", Network = Transport.Both }]
};

await Test("IP/CIDR and port boundaries", () => Sync(() =>
{
    Assert(RuleParser.Networks("192.168.10.123/24,2001:db8::123/64").SequenceEqual(new[] { "192.168.10.0/24", "2001:db8::/64" }), "normalization");
    foreach (var bad in new[] { "", "127.1", "010.0.0.1", "0x7f.0.0.1", "1.2.3.4/33", "::/129", "1.2.3.4,,2.2.2.2", "fe80::1%2" }) Reject(() => RuleParser.Networks(bad));
    foreach (var bad in new[] { "", "0", "65536", "9000-8000", "80,", "* ,443" }) Reject(() => RuleParser.Ports(bad));
    Assert(RuleParser.Ports("1,443,8000-9000,65535").Length == 4, "ports");
}));
await Test("Selective IP policy, first match and process restrictions", () => Sync(() =>
{
    var profile = Example(); var rule = profile.Rules[0];
    foreach (var all in new[] { "*", "0.0.0.0/0", "::/0" }) { rule.Destinations = all; _ = new CapturePlan(profile); }
    rule.Destinations = "203.0.113.10"; rule.ProcessName = "client.exe"; rule.Ports = "443,8000-9000";
    var plan = new CapturePlan(profile);
    Assert(plan.Match(IPAddress.Parse("203.0.113.10"), 443, false, "client") is not null, "selected");
    Assert(plan.Match(IPAddress.Parse("203.0.113.11"), 443, false, "client") is null, "unselected IP");
    Assert(plan.Match(IPAddress.Parse("203.0.113.10"), 443, false, "other") is null, "unselected program");
    Assert(plan.Match(IPAddress.Parse("203.0.113.10"), 53, true, "client") is null, "unselected port");
    profile.Proxies[0].Kind = ProxyKind.Http; Reject(() => new CapturePlan(profile));
    rule.Network = Transport.Tcp; _ = new CapturePlan(profile);
    profile.Rules.Insert(0, rule with { ProxyId = "direct" });
    Assert(new CapturePlan(profile).Match(IPAddress.Parse("203.0.113.10"), 443, false, "client")!.Proxy is null, "first direct exception");
}));
await Test("Pinned native library and selective filter compilation (no driver opened)", () => Sync(() =>
{
    var profile = Example(); profile.Rules.Add(profile.Rules[0] with { Destinations = "2001:db8::/32", Ports = "443,8000-9000" });
    var plan = new CapturePlan(profile); var filter = plan.Filter(23456, 23457);
    DivertEngine.CheckFilter(filter);
    Assert(filter.Contains("203.0.113.10") && filter.Contains("2001:db8::") && filter.Contains("outbound and !loopback"), "specific filter");
    byte[] Outgoing(string ip) => IpPacket.UdpReply(new FlowKey(IPAddress.Parse(ip), 53, IPAddress.Parse("192.0.2.1"), 51000, true), "test"u8);
    Assert(WinDivertNative.Evaluate(filter, Outgoing("203.0.113.10")), "native match selected IP");
    Assert(!WinDivertNative.Evaluate(filter, Outgoing("203.0.113.11")), "native bypass unselected IP");
}));
await Test("IPv4/IPv6 packet parsing, original destination and reverse NAT", () => Sync(() =>
{
    foreach (var v6 in new[] { false, true })
    {
        var key = new FlowKey(IPAddress.Parse(v6 ? "2001:db8::1" : "192.0.2.1"), 51000, IPAddress.Parse(v6 ? "2001:db8::2" : "203.0.113.2"), 443, true);
        var raw = IpPacket.UdpReply(key, "payload"u8);
        Assert(IpPacket.TryParse(raw, out var parsed), "parse UDP");
        Assert(parsed.Key(raw).LocalAddress.Equals(key.RemoteAddress) && parsed.Key(raw).LocalPort == 443, "reply source");
        Assert(raw.AsSpan(parsed.PayloadOffset).SequenceEqual("payload"u8), "payload preserved");
        parsed.Rewrite(raw, key.LocalAddress, 12345, key.RemoteAddress, 23456);
        Assert(IpPacket.TryParse(raw, out var changed) && changed.Key(raw).LocalPort == 12345, "translation");
        Assert(!IpPacket.TryParse(raw.AsSpan(0, raw.Length - 1), out _), "truncation");
    }
    var tcp = new byte[40]; tcp[0] = 0x45; tcp[9] = 6; tcp[2] = 0; tcp[3] = 40; tcp[32] = 0x50; tcp[33] = 2;
    IPAddress.Parse("192.0.2.1").GetAddressBytes().CopyTo(tcp, 12); IPAddress.Parse("203.0.113.10").GetAddressBytes().CopyTo(tcp, 16);
    BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(20), 51000); BinaryPrimitives.WriteUInt16BigEndian(tcp.AsSpan(22), 443);
    Assert(IpPacket.TryParse(tcp, out var packet), "TCP parse");
    var original = packet.Key(tcp); packet.Rewrite(tcp, original.RemoteAddress, 12345, original.LocalAddress, 23456);
    Assert(IpPacket.TryParse(tcp, out var redirected) && redirected.Key(tcp).RemotePort == 23456, "TCP listener redirect");
    redirected.Rewrite(tcp, original.LocalAddress, original.LocalPort, original.RemoteAddress, original.RemotePort);
    Assert(IpPacket.TryParse(tcp, out var restored) && restored.Key(tcp) == original, "TCP exact tuple restoration");
    tcp[6] = 0x20; Assert(IpPacket.TryParse(tcp, out var fragment) && fragment.Fragmented, "fragment detection");
}));
await Test("TCP mapping collisions and UDP memory bounds", () => Sync(() =>
{
    var table = new TcpFlowTable(); var route = new CapturePlan(Example()).Entries[0];
    var first = new FlowKey(IPAddress.Parse("192.0.2.1"), 51000, IPAddress.Parse("203.0.113.10"), 443, false);
    var a = table.Create(first, route, 100, 23000, 23001)!;
    var b = table.Create(first with { RemotePort = 8443 }, route, 200, 23000, 23001)!;
    Assert(a.VirtualPort != b.VirtualPort, "same source port / different destination collision");
    Assert(table.Accept(new IPEndPoint(first.RemoteAddress, a.VirtualPort), new IPEndPoint(first.LocalAddress, 23000)) == a, "attributed accept");
    Assert(table.Accept(new IPEndPoint(first.RemoteAddress, a.VirtualPort), new IPEndPoint(first.LocalAddress, 23000)) is null, "duplicate accept rejected");
    var budget = new DatagramBudget(); Assert(budget.TryReserve(16 * 1024 * 1024), "budget full"); Assert(!budget.TryReserve(1), "overload rejected"); budget.Release(16 * 1024 * 1024); Assert(budget.TryReserve(1), "budget recovered");
    var bypass = new SocketBypass(); var oldLease = bypass.Register(false, 50000); using var newLease = bypass.Register(false, 50000);
    oldLease.Dispose(); Assert(bypass.Contains(false, 50000), "old socket disposal must not remove a reused port registration");
}));
await Test("DPAPI persistence and corrupt profile preservation", () => Sync(() =>
{
    var folder = Path.Combine(Path.GetTempPath(), "ProxyWin-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new ProfileStore(folder); var profile = Example(); profile.Proxies[0].Username = "user"; profile.Proxies[0].Password = "local-test-secret";
        profile.Rules[0].ProcessName = "sample.exe"; store.Save(profile);
        Assert(store.Load().Proxies[0].Password == "local-test-secret" && store.Load().Rules[0].ProcessName == "sample.exe", "roundtrip");
        var file = Path.Combine(folder, "profile.dat"); Assert(!Encoding.UTF8.GetString(File.ReadAllBytes(file)).Contains("local-test-secret"), "encrypted");
        File.WriteAllBytes(file, [1, 2, 3]); var rejected = false;
        try { store.Load(); } catch (System.ComponentModel.Win32Exception) { rejected = true; }
        Assert(rejected && File.ReadAllBytes(file).Length == 3, "corrupt file unchanged");
    }
    finally { Directory.Delete(folder, true); }
}));
await Test("Real SOCKS5/HTTP handshakes preserve original IP and reject failures", async () =>
{
    foreach (var http in new[] { false, true })
    {
        await using var server = new TestProxy(http ? "http" : "socks", http: http);
        var proxy = new ProxyServer { Host = "127.0.0.1", Port = server.Port, Kind = http ? ProxyKind.Http : ProxyKind.Socks5 };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var endpoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443);
        using var connection = await ProxyConnector.OpenAsync(proxy, new IPEndPoint(IPAddress.Loopback, server.Port), endpoint, new SocketBypass(), timeout.Token);
        await connection.Stream.WriteAsync("ping"u8.ToArray(), timeout.Token); using var output = new MemoryStream(); await connection.Stream.CopyToAsync(output, timeout.Token);
        Assert(Encoding.ASCII.GetString(output.ToArray()) == (http ? "http:ping" : "socks:ping"), "reply");
        Assert(server.RequestedDestinations.Contains("203.0.113.10:443"), "original numeric destination");
    }
    await using var refusing = new TestProxy("refuse", reject: true);
    var rejected = false;
    try { using var connection = await ProxyConnector.OpenAsync(new ProxyServer(), new IPEndPoint(IPAddress.Loopback, refusing.Port), new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443), new SocketBypass(), CancellationToken.None); }
    catch (IOException) { rejected = true; }
    Assert(rejected, "SOCKS failure must not become direct connection");
});
await Test("SOCKS5 UDP association and original reply endpoint", async () =>
{
    await using var server = new TestProxy("udp");
    var key = new FlowKey(IPAddress.Parse("192.0.2.1"), 51001, IPAddress.Parse("203.0.113.10"), 53, true);
    var reply = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
    var error = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
    using var association = new UdpAssociation(key, new ProxyServer(), new IPEndPoint(IPAddress.Loopback, server.Port), new SocketBypass(), new DatagramBudget(), b => reply.TrySetResult(b), (_, _) => { }, e => error.TrySetResult(e), CancellationToken.None);
    Assert(association.Enqueue("ping"u8), "queue");
    var response = await reply.Task.WaitAsync(TimeSpan.FromSeconds(10));
    Assert(IpPacket.TryParse(response, out var packet) && packet.Key(response).LocalAddress.Equals(key.RemoteAddress), "original source");
    Assert(Encoding.ASCII.GetString(response.AsSpan(packet.PayloadOffset)) == "udp:ping", "UDP payload");
    association.Dispose(); await association.Completion;
    Assert(!error.Task.IsCompleted, "clean cancellation");
    Assert(!ProxyConnector.TryDecodeDatagram([0, 0, 1, 1, 0, 0, 0, 0, 0, 0], out _, out _), "fragmented SOCKS datagram rejected");
});
await Test("SOCKS5 authentication success and failure", async () =>
{
    await using var server = new TestProxy("auth", username: "test-user", password: "test-pass");
    var proxy = new ProxyServer { Username = "test-user", Password = "test-pass" };
    var endpoint = new IPEndPoint(IPAddress.Loopback, server.Port); var destination = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443);
    using (var connection = await ProxyConnector.OpenAsync(proxy, endpoint, destination, new SocketBypass(), CancellationToken.None))
    {
        await connection.Stream.WriteAsync("ping"u8.ToArray()); var reply = new byte[9]; await connection.Stream.ReadExactlyAsync(reply);
        Assert(Encoding.ASCII.GetString(reply) == "auth:ping", "authenticated payload");
    }
    proxy.Password = "wrong"; var rejected = false;
    try { using var connection = await ProxyConnector.OpenAsync(proxy, endpoint, destination, new SocketBypass(), CancellationToken.None); }
    catch (IOException) { rejected = true; }
    Assert(rejected, "wrong password rejected");
});
await Test("32 MiB TCP relay integrity, half-close and local throughput without driver", async () =>
{
    await using var server = new TestProxy("bulk", streaming: true);
    var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
    async Task Relay()
    {
        using var accepted = await listener.AcceptTcpClientAsync(timeout.Token); accepted.NoDelay = true;
        using var proxy = await ProxyConnector.OpenAsync(new ProxyServer(), new IPEndPoint(IPAddress.Loopback, server.Port),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443), new SocketBypass(), timeout.Token);
        await ProxyConnector.RelayAsync(accepted, proxy, (_, _) => { }, timeout.Token);
    }
    var relay = Relay();
    Exception? primary = null;
    try { await RunClient("bulk", ((IPEndPoint)listener.LocalEndpoint).Port, "", 1, "127.0.0.1"); await relay; }
    catch (Exception ex) { primary = ex; throw; }
    finally
    {
        timeout.Cancel(); listener.Stop();
        try { await relay; }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (primary is not null) { Console.WriteLine("Secondary relay shutdown: " + ex.Message); }
    }
});

await Test("FLOW metadata ABI, IPv4/IPv6 addresses, PID and host-order ports", () => Sync(() =>
{
    Assert(System.Runtime.InteropServices.Marshal.SizeOf<DivertAddress>() == 80, "native address size unchanged");
    var address = new DivertAddress
    {
        Flags = 2 | (1u << 8) | (1u << 17), FlowProcessId = 1234, FlowProtocol = 17,
        FlowLocal0 = 0xc0000201, FlowLocal1 = 0xffff, FlowLocalPort = 52000,
        FlowRemote0 = 0xcb00710a, FlowRemote1 = 0xffff, FlowRemotePort = 443
    };
    var row = ConnectionObserver.Decode(address, (_, _) => "sample.exe")!;
    Assert(row.LocalAddress.Equals(IPAddress.Parse("192.0.2.1")) && row.RemoteAddress.Equals(IPAddress.Parse("203.0.113.10")), "mapped IPv4 decoding");
    Assert(row.ProcessId == 1234 && row.LocalPort == 52000 && row.RemotePort == 443 && row.Network == Transport.Udp, "metadata");
    address.FlowRemote0 = 5; address.FlowRemote1 = 0; address.FlowRemote2 = 0; address.FlowRemote3 = 0x20010db8;
    Assert(ConnectionObserver.Decode(address, (_, _) => null)!.RemoteAddress.Equals(IPAddress.Parse("2001:db8::5")), "IPv6 word order");
    address.FlowProtocol = 1; Assert(ConnectionObserver.Decode(address) is null, "non TCP/UDP excluded");
    address.FlowProtocol = 6; address.Flags &= ~(1u << 17); Assert(ConnectionObserver.Decode(address) is null, "inbound excluded");
    address.Flags = 2 | (2u << 8) | (1u << 17); Assert(ConnectionObserver.Decode(address) is null, "deleted event excluded");
}));
await Test("Observation to exact rule, explicit program scope and unsupported endpoints", () => Sync(() =>
{
    var row = new ObservedConnection(DateTimeOffset.Now, 1234, "chrome.exe", IPAddress.Parse("192.0.2.1"), 53000, IPAddress.Parse("203.0.113.10"), 443, Transport.Tcp, false);
    var rule = row.CreateRule("s", true);
    Assert(rule.Destinations == "203.0.113.10" && rule.Ports == "443" && rule.Network == Transport.Tcp && rule.ProcessName == "chrome.exe", "exact scope");
    Assert(row.CreateRule("s", false).ProcessName == "", "explicit all-program choice");
    var unknown = row with { ProcessName = null }; Reject(() => unknown.CreateRule("s", true));
    Assert(unknown.CreateRule("s", false).ProcessName == "", "no silent program broadening");
    foreach (var local in new[] { row with { Loopback = true }, row with { RemoteAddress = IPAddress.Loopback }, row with { RemoteAddress = IPAddress.Parse("224.0.0.251") }, row with { RemoteAddress = IPAddress.Parse("fe80::1") } })
        Reject(() => local.CreateRule("s", false));
    Assert((row with { RemoteAddress = IPAddress.Parse("2001:db8::5"), Network = Transport.Udp }).CreateRule("s", true).Network == Transport.Udp, "IPv6 UDP preserved");
}));
await Test("DIRECT/PROXY/BLOCK order, independent actions and legacy profile compatibility", () => Sync(() =>
{
    var legacy = System.Text.Json.JsonSerializer.Deserialize<Profile>("""{"Version":1,"Proxies":[{"Id":"s","Host":"127.0.0.1"}],"Rules":[{"Destinations":"203.0.113.10","ProxyId":"s"},{"Destinations":"203.0.113.20","ProxyId":"direct"}]}""")!;
    RuleParser.Validate(legacy);
    Assert(legacy.Rules[0].Action == RuleAction.Proxy && legacy.Rules[1].Action == RuleAction.Direct, "legacy interpretation preserved");
    var direct = new RoutingRule { Destinations = "203.0.113.10", Ports = "443", Action = RuleAction.Direct };
    var block = direct with { Action = RuleAction.Block, Network = Transport.Both };
    var directOnly = new CapturePlan(new Profile { Rules = [direct] });
    Assert(directOnly.Filter(23000, 23001) == "false", "direct-only rules capture nothing");
    var profile = new Profile { Rules = [direct, block] };
    var plan = new CapturePlan(profile);
    Assert(plan.Match(IPAddress.Parse("203.0.113.10"), 443, false)!.Action == RuleAction.Direct, "direct exception first");
    Assert(plan.Match(IPAddress.Parse("203.0.113.10"), 443, true)!.Action == RuleAction.Block, "UDP block");
    profile.Rules.Reverse(); Assert(new CapturePlan(profile).Match(IPAddress.Parse("203.0.113.10"), 443, false)!.Action == RuleAction.Block, "block first");
    profile.Rules = [block]; DivertEngine.CheckFilter(new CapturePlan(profile).Filter(23000, 23001));
    var bad = block with { Action = RuleAction.Proxy, ProxyId = "missing" }; Reject(() => new CapturePlan(new Profile { Rules = [bad] }));
    var row = new ObservedConnection(DateTimeOffset.Now, 1, "test.exe", IPAddress.Parse("192.0.2.1"), 52000, IPAddress.Parse("203.0.113.10"), 443, Transport.Udp, false);
    Assert(row.CreateRule("", true, RuleAction.Block).Action == RuleAction.Block, "observation block without server");
}));
await Test("Version-2 encrypted actions roundtrip prevents old apps ignoring BLOCK", () => Sync(() =>
{
    var folder = Path.Combine(Path.GetTempPath(), "ProxyWin-actions-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new ProfileStore(folder);
        store.Save(new Profile { Version = 1, Rules = [new RoutingRule { Destinations = "203.0.113.10", Action = RuleAction.Block, Network = Transport.Both }] });
        var loaded = store.Load();
        Assert(loaded.Version == 2 && loaded.Rules[0].Action == RuleAction.Block, "version/action retained");
        Assert(new CapturePlan(loaded).Entries[0].Action == RuleAction.Block, "saved rule blocks");
    }
    finally { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
}));
await Test("Wildcard process rules match both IP families and preserve order / scope", () => Sync(() =>
{
    var profile = Example(); var rule = profile.Rules[0];
    rule.Destinations = "*"; rule.Ports = "*"; rule.ProcessName = "worker.exe";
    var plan = new CapturePlan(profile);
    foreach (var ip in new[] { "198.51.100.1", "203.0.113.99", "2001:db8::50" })
    {
        foreach (var udp in new[] { false, true })
        {
            Assert(plan.Match(IPAddress.Parse(ip), 54321, udp, "WORKER")?.Action == RuleAction.Proxy, "process-only wildcard");
            Assert(plan.Match(IPAddress.Parse(ip), 54321, udp, "other") is null, "other executable excluded");
        }
    }
    var exact = rule with { Destinations = "203.0.113.99", Action = RuleAction.Direct, ProcessName = "" };
    profile.Rules.Insert(0, exact);
    Assert(new CapturePlan(profile).Match(IPAddress.Parse("203.0.113.99"), 443, false)?.Action == RuleAction.Direct, "first unconditional exception needs no process name");
    profile.Rules = [rule with { Destinations = "0.0.0.0/0" }]; plan = new CapturePlan(profile);
    Assert(plan.Match(IPAddress.Parse("198.51.100.1"), 443, false, "worker") is not null, "IPv4 /0");
    Assert(plan.Match(IPAddress.Parse("2001:db8::1"), 443, false, "worker") is null, "IPv4 /0 stays IPv4");
    Reject(() => RuleParser.Networks("192.168.*.*"));
    Reject(() => RuleParser.Networks("*,203.0.113.10"));
}));
await Test("Wildcard native filter and serialized wildcard destination", () => Sync(() =>
{
    var profile = Example(); profile.Rules[0].Destinations = "*"; profile.Rules[0].Ports = "7446"; profile.Rules[0].ProcessName = "worker.exe";
    var filter = new CapturePlan(profile).Filter(23000, 23001); DivertEngine.CheckFilter(filter);
    foreach (var ip in new[] { "203.0.113.10", "2001:db8::10" })
    {
        var remote = IPAddress.Parse(ip); var local = IPAddress.Parse(remote.AddressFamily == AddressFamily.InterNetwork ? "192.0.2.1" : "2001:db8:1::1");
        var packet = IpPacket.UdpReply(new FlowKey(remote, 7446, local, 51000, true), "wildcard"u8);
        Assert(WinDivertNative.Evaluate(filter, packet), "native any-IP UDP filter");
        packet = IpPacket.UdpReply(new FlowKey(remote, 7447, local, 51000, true), "wildcard"u8);
        Assert(!WinDivertNative.Evaluate(filter, packet), "port restriction retained");
    }
    var copy = System.Text.Json.JsonSerializer.Deserialize<Profile>(System.Text.Json.JsonSerializer.Serialize(profile))!;
    Assert(copy.Rules[0].Destinations == "*" && copy.Rules[0].ProcessName == "worker.exe", "wildcard persisted without expanding scope");
}));

if (args.Contains("--driver"))
{
    await Test("Actual wildcard destination with process-specific PROXY/BLOCK and nonmatching-process DIRECT", async () =>
    {
        // Select UDP/TCP 7446; only the uniquely named test executable matches.
        // Fragments are also captured by the engine. Traffic uses documentation IPs.
        using var sink = WinDivertNative.Open("outbound and (ip.DstAddr == 203.0.113.10 or ip.DstAddr == 203.0.113.11) and ((tcp and tcp.DstPort == 7446) or (udp and udp.DstPort == 7446))", -100);
        await using var proxy = new TestProxy("wild"); using var self = Process.GetCurrentProcess();
        Assert(self.ProcessName == "ProxyWin.Tests", "run elevated wildcard tests through the isolated test apphost");
        var profile = new Profile
        {
            Proxies = [new ProxyServer { Id = "wild", Host = "127.0.0.1", Port = proxy.Port }],
            Rules = [new RoutingRule { Destinations = "*", Ports = "7446", Network = Transport.Both, ProcessName = self.ProcessName + ".exe", ProxyId = "wild", Action = RuleAction.Proxy }]
        };
        await using var engine = new DivertEngine();
        try
        {
            await engine.StartAsync(profile);
            await RunClient("tcp", 7446, "wild:ping", 1);
            await RunClient("udp", 7446, "wild:ping", 1, "203.0.113.11");
            await engine.StopAsync();
            profile.Rules[0].Action = RuleAction.Block; await engine.StartAsync(profile);
            await RunClient("block-tcp", 7446, "", 1); await RunClient("block-udp", 7446, "", 1, "203.0.113.11");
            Assert(engine.Statistics.Blocked >= 2, "wildcard block for matching executable");
            await engine.StopAsync();
            profile.Rules[0].ProcessName = "not-this-process.exe"; await engine.StartAsync(profile);
            await RunClient("block-udp", 7446, "", 1); // Unmatched process passes to the sink without a reply.
            Assert(engine.Statistics.Blocked == 0, "nonmatching process not blocked");
            Assert(WinDivertNative.WinDivertShutdown(sink, WinDivertNative.ShutdownReceive), "sink shutdown");
            var passed = ReadSink(sink);
            Assert(passed is not null && IpPacket.TryParse(passed, out var packet) && packet.Key(passed).RemotePort == 7446 && passed.AsSpan(packet.PayloadOffset).SequenceEqual("ping"u8), "only unmatched-process datagram passed unchanged");
            Assert(ReadSink(sink) is null, "matching wildcard rules did not leak test traffic");
        }
        finally { await engine.StopAsync(); }
    });
    await Test("Actual BLOCK TCP/UDP without a proxy and DIRECT priority exception", async () =>
    {
        // A lower-priority test sink consumes any passed test traffic so none leaves the host.
        using var sink = WinDivertNative.Open("outbound and ip.DstAddr == 203.0.113.10 and ((tcp and tcp.DstPort == 7443) or (udp and (udp.DstPort == 7444 or udp.DstPort == 7445)))", -100);
        var profile = new Profile { Rules = [
            new RoutingRule { Destinations = "203.0.113.10", Ports = "7445", Network = Transport.Udp, Action = RuleAction.Direct },
            new RoutingRule { Destinations = "203.0.113.10", Ports = "7443-7445", Network = Transport.Both, Action = RuleAction.Block }
        ] };
        await using var engine = new DivertEngine(); await engine.StartAsync(profile);
        try
        {
            await RunClient("block-tcp", 7443, "", 1); await RunClient("block-udp", 7444, "", 1);
            Assert(engine.Statistics.Blocked >= 2 && engine.Statistics.Uploaded == 0, "both transports blocked without upstream");
            var blockedBefore = engine.Statistics.Blocked;
            await RunClient("block-udp", 7445, "", 1); // DIRECT reaches the sink, which intentionally gives no reply.
            Assert(engine.Statistics.Blocked == blockedBefore, "DIRECT wins before BLOCK");
            Assert(WinDivertNative.WinDivertShutdown(sink, WinDivertNative.ShutdownReceive), "finish sink capture");
            var passed = ReadSink(sink);
            Assert(passed is not null && IpPacket.TryParse(passed, out var packet) && packet.Key(passed).RemotePort == 7445
                && passed.AsSpan(packet.PayloadOffset).SequenceEqual("ping"u8), "only DIRECT passes unchanged to lower-priority sink");
            Assert(ReadSink(sink) is null, "blocked packets were never reinjected");
        }
        finally { await engine.StopAsync(); }
    });
    await Test("Read-only FLOW observer: TCP/UDP PID attribution, traffic unaffected, stop/restart", async () =>
    {
        await using var observer = new ConnectionObserver();
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var udpListener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await observer.StartAsync(Environment.ProcessId);
            var accept = listener.AcceptTcpClientAsync(timeout.Token);
            using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
            using var peer = await accept;
            await tcp.GetStream().WriteAsync("observe"u8.ToArray(), timeout.Token);
            var data = new byte[7]; await peer.GetStream().ReadExactlyAsync(data, timeout.Token);
            Assert(data.AsSpan().SequenceEqual("observe"u8), "observer must not change TCP payload");
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            await udp.SendAsync("observe"u8.ToArray(), (IPEndPoint)udpListener.Client.LocalEndPoint!, timeout.Token);
            var datagram = await udpListener.ReceiveAsync(timeout.Token);
            Assert(datagram.Buffer.AsSpan().SequenceEqual("observe"u8), "observer must not change UDP payload");
            var tcpSeen = false; var udpSeen = false;
            using var self = Process.GetCurrentProcess();
            while (!tcpSeen || !udpSeen)
            {
                while (observer.TryRead(out var row))
                {
                    Assert(row!.ProcessId == Environment.ProcessId, "only the scoped test process is observed");
                    Assert(row.ProcessName == self.ProcessName + ".exe", "correct process name");
                    if (row.RemoteAddress.Equals(IPAddress.Loopback) && row.Loopback)
                    {
                        if (row.Network == Transport.Tcp && row.RemotePort == ((IPEndPoint)listener.LocalEndpoint).Port) tcpSeen = true;
                        if (row.Network == Transport.Udp && row.RemotePort == ((IPEndPoint)udpListener.Client.LocalEndPoint!).Port) udpSeen = true;
                    }
                }
                if (!tcpSeen || !udpSeen) await Task.Delay(20, timeout.Token);
            }
            await observer.StopAsync().WaitAsync(TimeSpan.FromSeconds(5)); Assert(!observer.IsRunning && observer.LastError is null, "clean stop");
            observer.Clear(); await observer.StartAsync(Environment.ProcessId);
            using var next = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            await next.SendAsync("again"u8.ToArray(), (IPEndPoint)udpListener.Client.LocalEndPoint!, timeout.Token);
            await udpListener.ReceiveAsync(timeout.Token);
            var restarted = false;
            while (!restarted)
            {
                while (observer.TryRead(out var row)) restarted |= row!.Network == Transport.Udp && row.LocalPort == ((IPEndPoint)next.Client.LocalEndPoint!).Port;
                if (!restarted) await Task.Delay(20, timeout.Token);
            }
            await observer.StopAsync().WaitAsync(TimeSpan.FromSeconds(5)); Assert(observer.LastError is null, "clean restart");
        }
        finally { listener.Stop(); await observer.StopAsync(); }
    });
    await Test("Actual WinDivert TCP/UDP redirection, concurrent flows, HTTP and restart", async () =>
    {
        using var identity = WindowsIdentity.GetCurrent();
        Assert(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator), "Driver test requires Windows Administrator");
        await using var socks = new TestProxy("socks"); await using var http = new TestProxy("http", http: true);
        await using var bulk = new TestProxy("bulk", streaming: true);
        using var self = Process.GetCurrentProcess();
        var profile = new Profile
        {
            Proxies = [new ProxyServer { Id = "s", Host = "127.0.0.1", Port = socks.Port }, new ProxyServer { Id = "h", Host = "127.0.0.1", Port = http.Port, Kind = ProxyKind.Http }, new ProxyServer { Id = "b", Host = "127.0.0.1", Port = bulk.Port }],
            Rules = [new RoutingRule { Destinations = "203.0.113.10", Ports = "443,53", Network = Transport.Both, ProxyId = "s", ProcessName = self.ProcessName + ".exe" }, new RoutingRule { Destinations = "203.0.113.10", Ports = "8443", ProxyId = "h" }, new RoutingRule { Destinations = "203.0.113.10", Ports = "9443", ProxyId = "b" }]
        };
        await using var engine = new DivertEngine(); engine.Log += message => Console.WriteLine("  " + message);
        await engine.StartAsync(profile);
        try
        {
            Console.WriteLine("  Driver: TCP SOCKS5");
            await using (var observation = new ConnectionObserver())
            {
                await RunClient("tcp", 443, "socks:ping", 1, observer: observation);
                using var observationTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var originalSeen = false;
                while (!originalSeen)
                {
                    while (observation.TryRead(out var row)) originalSeen |= row!.RemoteAddress.Equals(IPAddress.Parse("203.0.113.10")) && row.RemotePort == 443 && row.Network == Transport.Tcp;
                    if (!originalSeen) await Task.Delay(20, observationTimeout.Token);
                }
                Assert(observation.LastError is null, "observation and redirection coexist");
                await observation.StopAsync();
                Console.WriteLine("  Observer: original destination retained while proxying");
            }
            Console.WriteLine("  Driver: UDP SOCKS5");
            await RunClient("udp", 53, "socks:ping", 1);
            Console.WriteLine("  Driver: TCP HTTP CONNECT");
            await RunClient("tcp", 8443, "http:ping", 1);
            await RunClient("tcp", 443, "socks:ping", 32);
            Console.WriteLine("  Driver: bulk integrity / half-close / throughput");
            await RunClient("bulk", 9443, "", 1);
            Assert(engine.Statistics.Uploaded >= 140 && engine.Statistics.Downloaded > 140, "real transferred counters");
        }
        finally { Console.WriteLine("  Driver statistics: " + engine.Statistics); foreach (var peerError in bulk.PeerErrors) Console.WriteLine("  Test peer: " + peerError); await engine.StopAsync(); }
        Assert(!engine.IsRunning, "stopped");
        await engine.StartAsync(profile); await RunClient("tcp", 443, "socks:ping", 1); await engine.StopAsync();
    });
}
else Console.WriteLine("SKIP actual driver interception (pass --driver from an elevated test host)");
Console.WriteLine($"{tests - failures}/{tests} passed");
return failures == 0 ? 0 : 1;

async Task RunClient(string protocol, int port, string expected, int count, string targetIp = "203.0.113.10", ConnectionObserver? observer = null)
{
    var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = observer is not null };
    if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Assembly.GetEntryAssembly()!.Location);
    foreach (var value in new[] { "--client", protocol, targetIp, port.ToString(), expected, count.ToString() }) start.ArgumentList.Add(value);
    if (observer is not null) start.ArgumentList.Add("--wait-start");
    using var process = Process.Start(start)!;
    var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(protocol == "bulk" ? 40 : 20));
    try
    {
        if (observer is not null)
        {
            await observer.StartAsync(process.Id);
            await process.StandardInput.WriteLineAsync("start"); process.StandardInput.Close();
        }
        await process.WaitForExitAsync(timeout.Token); var output = (await stdout) + (await stderr);
        Assert(process.ExitCode == 0, output); if (output.Length > 0) Console.WriteLine("  " + output.Trim());
    }
    finally { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); } }
}

unsafe byte[]? ReadSink(DivertHandle handle)
{
    var bytes = new byte[65575]; var addresses = new DivertAddress[1]; uint addressLength = 80;
    fixed (byte* pointer = bytes)
    {
        if (WinDivertNative.WinDivertRecvEx(handle, pointer, (uint)bytes.Length, out var received, 0, addresses, ref addressLength, IntPtr.Zero))
            return bytes[..(int)received];
        var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        if (error == 232) return null;
        throw new System.ComponentModel.Win32Exception(error);
    }
}
