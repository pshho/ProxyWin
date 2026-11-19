using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using ProxyWin.Core;
using ProxyWin.Windows;

// proxy_all 검토 항목 회귀 테스트: 드라이버 없이 실행 가능한 범위만 다룬다.
internal static class RepairTests
{
    private static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    // F-7ad8b9 / F-a6e570: 조각은 목적지·프로토콜만으로 확정되는 판정을 따르고, 모호할 때만 폐기
    public static Task FragmentDecisions()
    {
        var proxy = new ProxyServer { Id = "s", Host = "127.0.0.1" };
        CapturePlan Plan(params RoutingRule[] rules) => new(new Profile { Proxies = [proxy], Rules = [.. rules] });
        var directLan = new RoutingRule { Destinations = "10.0.0.0/8", Action = RuleAction.Direct, Network = Transport.Both };
        var proxyAll = new RoutingRule { Destinations = "*", Action = RuleAction.Proxy, ProxyId = "s", Network = Transport.Both };
        var plan = Plan(directLan, proxyAll);
        Require(plan.ClassifyFragment(IPAddress.Parse("10.1.2.3"), 17) == FragmentDecision.Pass, "Fragments for a higher-priority DIRECT rule were dropped");
        Require(plan.ClassifyFragment(IPAddress.Parse("203.0.113.10"), 17) == FragmentDecision.Drop, "PROXY fragments cannot be relayed and must be dropped");
        Require(plan.ClassifyFragment(IPAddress.Parse("203.0.113.10"), 1) == FragmentDecision.Pass, "ICMP fragments are outside TCP/UDP rules");
        var tcp443 = new RoutingRule { Destinations = "203.0.113.10", Ports = "443", Action = RuleAction.Block };
        plan = Plan(tcp443);
        Require(plan.ClassifyFragment(IPAddress.Parse("203.0.113.10"), 17) == FragmentDecision.Pass, "A TCP-only rule dropped UDP fragments to the same IP");
        Require(plan.ClassifyFragment(IPAddress.Parse("203.0.113.10"), 6) == FragmentDecision.Drop, "Port-conditioned BLOCK fragments are ambiguous");
        plan = Plan(tcp443 with { Ports = "*", Network = Transport.Both });
        Require(plan.ClassifyFragment(IPAddress.Parse("203.0.113.10"), 17) == FragmentDecision.Block, "Unconditional BLOCK fragments must count as blocked");
        plan = Plan(directLan with { Ports = "53" }, proxyAll);
        Require(plan.ClassifyFragment(IPAddress.Parse("10.1.2.3"), 17) == FragmentDecision.Drop, "Conditional DIRECT before PROXY is ambiguous");
        plan = Plan(directLan with { ProcessName = "a.exe" }, directLan with { Destinations = "*" });
        Require(plan.ClassifyFragment(IPAddress.Parse("10.1.2.3"), 17) == FragmentDecision.Pass, "Only DIRECT outcomes remain, so fragments must pass");
        // IPv6 확장 헤더(60) 뒤라 상위 프로토콜을 모르는 조각은 TCP 전용 BLOCK도 우회하면 안 된다.
        plan = Plan(tcp443 with { Destinations = "2001:db8::10", Ports = "*" });
        Require(plan.ClassifyFragment(IPAddress.Parse("2001:db8::10"), 60) == FragmentDecision.Drop, "Unknown-transport IPv6 fragments bypassed a TCP BLOCK");
        plan = Plan(tcp443 with { Destinations = "2001:db8::10", Ports = "*", Network = Transport.Both });
        Require(plan.ClassifyFragment(IPAddress.Parse("2001:db8::10"), 60) == FragmentDecision.Block, "Unknown-transport fragments must follow an unconditional TCP+UDP BLOCK");
        Require(plan.ClassifyFragment(IPAddress.Parse("2001:db8::11"), 60) == FragmentDecision.Pass, "Unmatched unknown-transport fragments must pass");
        return Task.CompletedTask;
    }

    // F-3387f7 / F-16e051: 배치 중 파싱 실패 패킷 뒤의 정상 패킷을 계속 처리 / F-3792a5: IPv6 UDP 응답 크기
    public static Task BatchFrameLengths()
    {
        var key4 = new FlowKey(IPAddress.Parse("192.0.2.1"), 5000, IPAddress.Parse("203.0.113.1"), 53, true);
        var key6 = new FlowKey(IPAddress.Parse("2001:db8::1"), 5000, IPAddress.Parse("2001:db8::2"), 53, true);
        var v4 = IpPacket.UdpReply(key4, "abc"u8);
        var v6 = IpPacket.UdpReply(key6, "abcd"u8);
        var broken = v4.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(broken.AsSpan(24), 9);
        var batch = broken.Concat(v6).ToArray();
        Require(!IpPacket.TryParse(batch, out _), "Fixture must fail parsing");
        Require(IpPacket.TryGetFrameLength(batch, out var skip) && skip == broken.Length, "IPv4 frame length");
        Require(IpPacket.TryParse(batch.AsSpan(skip), out var next) && next.Length == v6.Length, "Batch must continue after a bad packet");
        Require(IpPacket.TryGetFrameLength(v6, out var length6) && length6 == v6.Length, "IPv6 frame length");
        var jumbo = v6.ToArray(); jumbo[4] = 0; jumbo[5] = 0;
        Require(!IpPacket.TryGetFrameLength(jumbo, out _), "Unknown jumbogram length must stop the batch");
        Require(!IpPacket.TryGetFrameLength(v4.AsSpan(0, v4.Length - 1), out _), "Truncated frame");
        Require(IpPacket.UdpReply(key6, new byte[65527]).Length == 40 + 8 + 65527, "IPv6 replies carry up to 65527 bytes");
        try { IpPacket.UdpReply(key6, new byte[65528]); throw new Exception("Oversized IPv6 reply accepted"); } catch (ArgumentOutOfRangeException) { }
        try { IpPacket.UdpReply(key4, new byte[65508]); throw new Exception("Oversized IPv4 reply accepted"); } catch (ArgumentOutOfRangeException) { }
        return Task.CompletedTask;
    }

    // F-d109e0 / F-9ec27d: 같은 포트 번호라도 주소 계열이 다르면 우회 대상이 아니다
    public static Task BypassFamilies()
    {
        var bypass = new SocketBypass();
        using (bypass.Register(false, AddressFamily.InterNetwork, 50001))
        {
            Require(bypass.Contains(false, AddressFamily.InterNetwork, 50001), "IPv4 registration");
            Require(!bypass.Contains(false, AddressFamily.InterNetworkV6, 50001), "An IPv4 relay port exempted an IPv6 socket with the same number");
            Require(!bypass.Contains(true, AddressFamily.InterNetwork, 50001), "A TCP registration exempted UDP");
        }
        Require(bypass.Count == 0, "Family registration released");
        using (bypass.Register(true, 50002))
            Require(bypass.Contains(true, AddressFamily.InterNetwork, 50002) && bypass.Contains(true, AddressFamily.InterNetworkV6, 50002), "Dual-mode registration covers both families");
        Require(bypass.Count == 0, "Dual-mode registration released");
        var plan = new CapturePlan(new Profile { Proxies = [new ProxyServer { Id = "s", Host = "127.0.0.1" }], Rules = [new RoutingRule { Destinations = "*", Action = RuleAction.Proxy, ProxyId = "s" }] });
        var filter = plan.Filter(23000, 23001);
        Require(filter.Contains("(ip and tcp.SrcPort == 23000)") && filter.Contains("(ipv6 and tcp.SrcPort == 23001)"), "Listener replies must be captured per address family");
        return Task.CompletedTask;
    }

    // F-6c56ec: 닫힌 흐름이 상한을 채워도 새 SYN이 막히지 않음 / F-33e936: 링크로컬 ScopeId 무시
    public static Task FlowTableRepairs()
    {
        var route = new CapturePlan(new Profile { Rules = [new RoutingRule { Destinations = "*", Action = RuleAction.Block }] }).Entries[0];
        var table = new TcpFlowTable();
        var key = new FlowKey(IPAddress.Parse("192.0.2.1"), 1, IPAddress.Parse("203.0.113.10"), 443, false);
        var flows = new List<TcpFlow>();
        for (var i = 0; i < TcpFlowTable.Capacity; i++)
        {
            var flow = table.Create(key with { LocalPort = i + 1 }, route, 1, 10001, 10002);
            Require(flow is not null, "Initial capacity");
            flows.Add(flow!);
        }
        // F-1a0b77: 방금 닫힌 흐름은 최소 보존 시간 동안 회수하지 않는다.
        foreach (var flow in flows) table.MarkClosed(flow);
        Require(table.Create(key with { LocalPort = 60000 }, route, 1, 10001, 10002) is null, "Flows closed moments ago were reclaimed before the minimum retention");
        var aged = new TcpFlowTable();
        for (var i = 0; i < TcpFlowTable.Capacity; i++)
            aged.MarkClosed(aged.Create(key with { LocalPort = i + 1 }, route, 1, 10001, 10002)!, Environment.TickCount64 - TcpFlowTable.MinimumClosedRetention - 1000);
        Require(aged.Create(key with { LocalPort = 60000 }, route, 1, 10001, 10002) is not null, "Old closed flows blocked a new SYN at capacity");
        // F-4ac755 / F-b7e95e: 옛 흐름의 원래 주소 매핑만 끊고, 가상 포트 쪽(늦은 FIN 역변환용)은 남긴다.
        var stale = new TcpFlowTable();
        var old = stale.Create(key, route, 100, 10001, 10002)!;
        stale.MarkClosed(old); stale.Forget(key, old);
        Require(stale.Find(key) is null && stale.FindVirtual(old.VirtualPort) == old, "A new connection on the same 4-tuple must not reuse the closed proxy mapping");
        var linkKey = new FlowKey(IPAddress.Parse("fe80::1"), 50000, IPAddress.Parse("fe80::2"), 443, false);
        var linkTable = new TcpFlowTable();
        var linkFlow = linkTable.Create(linkKey, route, 1, 10001, 10002)!;
        var scopedPeer = new IPAddress(linkKey.RemoteAddress.GetAddressBytes(), 7);
        var scopedLocal = new IPAddress(linkKey.LocalAddress.GetAddressBytes(), 7);
        Require(linkTable.Accept(new IPEndPoint(scopedPeer, linkFlow.VirtualPort), new IPEndPoint(scopedLocal, 10002)) == linkFlow, "IPv6 ScopeId rejected a link-local flow");
        Require(!TcpFlowTable.SameAddress(IPAddress.Parse("192.0.2.1"), IPAddress.Parse("::ffff:192.0.2.1")), "Address families must stay distinct");
        return Task.CompletedTask;
    }

    // F-4fe889 / F-3bc790: 미리 계산한 매칭 값과 첫 후보 위치부터 이어 찾는 결과가 처음부터 찾는 결과와 같다
    public static Task PlanMatchingCache()
    {
        var plan = new CapturePlan(new Profile
        {
            Proxies = [new ProxyServer { Id = "s", Host = "127.0.0.1" }],
            Rules = [new RoutingRule { Destinations = "203.0.113.0/24", Ports = "443", Action = RuleAction.Proxy, ProxyId = "s", ProcessName = "Chrome.EXE" },
                new RoutingRule { Destinations = "203.0.113.10", Ports = "80, 443", Action = RuleAction.Block, Network = Transport.Both },
                new RoutingRule { Destinations = "*", Action = RuleAction.Direct, Network = Transport.Both }]
        });
        Require(plan.NeedsProcessLookup && plan.Entries[0].Program == "Chrome", "Process lookup flag / normalized program name");
        foreach (var ip in new[] { "203.0.113.10", "203.0.113.99", "198.51.100.1", "2001:db8::1" })
            foreach (var port in new[] { 80, 443, 8080 })
                foreach (var udp in new[] { false, true })
                    foreach (var name in new[] { "chrome", "CHROME", "other", null })
                    {
                        var address = IPAddress.Parse(ip);
                        var first = plan.FirstIndex(address, port, udp);
                        Require(ReferenceEquals(plan.Match(address, port, udp, name), plan.Match(address, port, udp, name, first)), $"Match from first candidate differs ({ip}:{port} udp={udp} {name})");
                    }
        Require(plan.Match(IPAddress.Parse("203.0.113.10"), 443, false, "chrome")?.Action == RuleAction.Proxy, "Process rule with .exe in the rule name");
        Require(plan.Match(IPAddress.Parse("203.0.113.10"), 443, false, "other")?.Action == RuleAction.Block, "Next rule after a process mismatch");
        var packet = IpPacket.UdpReply(new FlowKey(IPAddress.Parse("192.0.2.1"), 5000, IPAddress.Parse("203.0.113.1"), 53, true), "x"u8);
        Require(IpPacket.TryParse(packet, out var parsed), "Fixture parse");
        try { parsed.Rewrite(packet, IPAddress.Parse("2001:db8::1"), 1, IPAddress.Parse("2001:db8::2"), 2); throw new Exception("Address family mismatch was written into an IPv4 packet"); }
        catch (ArgumentException) { }
        return Task.CompletedTask;
    }

    // F-10f876: SOCKS5 UDP 응답 출발지 확인을 할당 없이 수행
    public static Task DatagramSourceMatching()
    {
        var v4 = IPAddress.Parse("203.0.113.10"); var v6 = IPAddress.Parse("2001:db8::10");
        byte[] Datagram(IPAddress address, int port) => new byte[] { 0, 0, 0 }.Concat(ProxyConnector.EncodeAddress(new IPEndPoint(address, port))).Concat("data"u8.ToArray()).ToArray();
        Require(ProxyConnector.TryMatchDatagram(Datagram(v4, 53), v4, 53, out var offset) && offset == 10, "IPv4 source match");
        Require(ProxyConnector.TryMatchDatagram(Datagram(v6, 53), v6, 53, out offset) && offset == 22, "IPv6 source match");
        Require(!ProxyConnector.TryMatchDatagram(Datagram(v4, 54), v4, 53, out _), "Wrong port accepted");
        Require(!ProxyConnector.TryMatchDatagram(Datagram(IPAddress.Parse("203.0.113.11"), 53), v4, 53, out _), "Wrong address accepted");
        Require(!ProxyConnector.TryMatchDatagram(Datagram(v6, 53), v4, 53, out _), "Different address family accepted");
        var fragment = Datagram(v4, 53); fragment[2] = 1;
        Require(!ProxyConnector.TryMatchDatagram(fragment, v4, 53, out _), "SOCKS fragment accepted");
        return Task.CompletedTask;
    }

    // F-a8b80e / F-a09b07: 프로세스 이름 직접 조회와 PID 재사용 판정
    public static Task ProcessNameLookup()
    {
        var pid = Environment.ProcessId;
        var expected = Path.GetFileName(Environment.ProcessPath!);
        Require(string.Equals(ProcessNames.FileName(pid), expected, StringComparison.OrdinalIgnoreCase), $"Image name lookup returned {ProcessNames.FileName(pid)}");
        Require(string.Equals(ProcessNames.FileName(pid), ProcessNames.FileName(pid), StringComparison.Ordinal), "Cached name differs");
        Require(string.Equals(SocketOwners.Name(pid), Path.GetFileNameWithoutExtension(expected), StringComparison.OrdinalIgnoreCase), "Rule comparison name keeps .exe");
        Require(ProcessNames.FileName(pid, DateTime.UtcNow.AddYears(-20)) is null, "A process created after the event time must not supply its name");
        return Task.CompletedTask;
    }

    // F-7c00e2: 한쪽이 반종료한 뒤 상대가 닫지 않아도 유휴 시간이 지나면 중계가 정상 종료된다
    public static async Task HalfCloseIdleTimeout()
    {
        var previous = ProxyConnector.HalfCloseIdle;
        ProxyConnector.HalfCloseIdle = TimeSpan.FromMilliseconds(400);
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            using var appListener = new TcpListener(IPAddress.Loopback, 0); appListener.Start();
            using var proxyListener = new TcpListener(IPAddress.Loopback, 0); proxyListener.Start();
            using var app = new TcpClient(); await app.ConnectAsync((IPEndPoint)appListener.LocalEndpoint, watchdog.Token);
            using var accepted = await appListener.AcceptTcpClientAsync(watchdog.Token);
            var upstream = new TcpClient(); await upstream.ConnectAsync((IPEndPoint)proxyListener.LocalEndpoint, watchdog.Token);
            using var silentPeer = await proxyListener.AcceptTcpClientAsync(watchdog.Token);
            using var connection = new ProxyConnection(upstream, new SocketBypass().Register(false, 1));
            var relay = ProxyConnector.RelayAsync(accepted, connection, (_, _) => { }, watchdog.Token);
            app.Client.Shutdown(SocketShutdown.Send);   // 앱은 FIN, 상대(silentPeer)는 끝까지 닫지 않음
            await relay.WaitAsync(TimeSpan.FromSeconds(5));
            Require(relay.IsCompletedSuccessfully, "Half-closed idle relay did not finish normally");
        }
        finally { ProxyConnector.HalfCloseIdle = previous; }
    }

    // F-e31ebc / F-3792a5: 예상 밖 예외가 UDP association의 Completion을 fault시키지 않는다
    public static async Task UdpUnexpectedFailureContained()
    {
        await using var server = new TestProxy("udp");
        var key = new FlowKey(IPAddress.Parse("192.0.2.1"), 51002, IPAddress.Parse("203.0.113.10"), 53, true);
        var error = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var association = new UdpAssociation(key, new ProxyServer(), new IPEndPoint(IPAddress.Loopback, server.Port), new SocketBypass(), new DatagramBudget(),
            _ => throw new InvalidOperationException("injected reply failure"), (_, _) => { }, e => error.TrySetResult(e), CancellationToken.None);
        Require(association.Enqueue("ping"u8), "Queue");
        var reported = await error.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try { await association.Completion.WaitAsync(TimeSpan.FromSeconds(10)); } catch (Exception) { }
        Require(association.Completion.IsCompletedSuccessfully, "An unexpected relay exception faulted Completion");
        Require(reported is InvalidOperationException, "The unexpected exception was not reported");
        Require(Volatile.Read(ref association.Finished) != 0, "Finish time was not recorded");
    }
}
