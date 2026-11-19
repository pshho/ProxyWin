using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProxyWin.Core;

namespace ProxyWin.Windows;

public readonly record struct RelayStatistics(long Uploaded, long Downloaded, long Dropped, long Errors, int TcpConnections, int UdpAssociations, long Blocked = 0);

public sealed class DivertEngine : IAsyncDisposable
{
    // TCP 직접 통과 판정 유지 시간 / UDP 판정 재사용 시간(포트 재사용 대비 짧게) / UDP 소유자 재검사 주기
    private const long PassthroughLifetime = 120000, UdpDecisionLifetime = 5000, OwnerRecheck = 2000, OwnerRetry = 250;
    // 재주입이 연속으로 전부 실패하면(핸들·드라이버 이상) 그때만 엔진을 멈춘다.
    private const int ReinjectFailureLimit = 16;
    private const int PassthroughCapacity = 32768;
    private readonly SemaphoreSlim gate = new(1, 1);
    private Session? session;
    private RelayStatistics last;
    public bool IsRunning => session is { Stopping: false };
    public RelayStatistics Statistics => session?.Statistics ?? last;
    public event Action<string>? Log;
    public event Action? Exited;

    private sealed class Session(CapturePlan plan, Dictionary<string, IPEndPoint> servers)
    {
        public CapturePlan Plan { get; } = plan;
        public Dictionary<string, IPEndPoint> Servers { get; } = servers;
        public LocalProxyOwnerCache LocalProxies { get; } = new(SocketOwners.LocalEndpoints(servers.Values));
        public CancellationTokenSource Stop { get; } = new();
        public TcpListener Listener4 { get; } = new(IPAddress.Any, 0);
        public TcpListener? Listener6 { get; } = Socket.OSSupportsIPv6 ? new(IPAddress.IPv6Any, 0) : null;
        public int Port4, Port6;
        public DivertHandle? Handle;
        public Task Capture = Task.CompletedTask, Accept4 = Task.CompletedTask, Accept6 = Task.CompletedTask, Maintenance = Task.CompletedTask;
        public TcpFlowTable Flows { get; } = new();
        public SocketBypass Bypass { get; } = new();
        public DatagramBudget Budget { get; } = new();
        public ConcurrentDictionary<FlowKey, UdpAssociation> Udp { get; } = new();
        public ConcurrentDictionary<int, Task> Tcp { get; } = new();
        public SemaphoreSlim TcpSlots { get; } = new(2048, 2048);
        public ConcurrentDictionary<FlowKey, long> Passthrough { get; } = new();
        public long Uploaded, Downloaded, Dropped, Errors, LastLog, Blocked;
        // ConcurrentDictionary.Count는 모든 버킷 락을 잡으므로 상한 판정·통계용 개수는 따로 센다.
        public long TcpCount, UdpCount, PassthroughCount;
        public int PassthroughTrimmed;
        public volatile bool Stopping;
        public RelayStatistics Statistics => new(Interlocked.Read(ref Uploaded), Interlocked.Read(ref Downloaded), Interlocked.Read(ref Dropped), Interlocked.Read(ref Errors),
            (int)Interlocked.Read(ref TcpCount), (int)Interlocked.Read(ref UdpCount), Interlocked.Read(ref Blocked));
        public void Count(int length, bool upload)
        {
            if (upload) Interlocked.Add(ref Uploaded, length); else Interlocked.Add(ref Downloaded, length);
        }
    }

    public static void CheckDriver() => WinDivertNative.VerifyFiles();
    public static void CheckFilter(string filter) { CheckDriver(); WinDivertNative.ValidateFilter(filter); }

    public async Task StartAsync(Profile profile)
    {
        var plan = new CapturePlan(profile);
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (session is not null) throw new InvalidOperationException("이미 규칙이 적용 중입니다.");
            CheckDriver();
            var servers = new Dictionary<string, IPEndPoint>();
            foreach (var proxy in plan.Entries.Select(e => e.Proxy).OfType<ProxyServer>().DistinctBy(p => p.Id))
            {
                // 서버마다 10초를 따로 주고, 시간 초과도 어느 서버의 문제인지 알 수 있게 안내한다.
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                IPAddress[] addresses;
                try { addresses = await Dns.GetHostAddressesAsync(proxy.Host, timeout.Token).ConfigureAwait(false); }
                catch (SocketException) { addresses = []; }
                catch (OperationCanceledException) when (timeout.IsCancellationRequested)
                {
                    throw new IOException($"프록시 서버 '{proxy.Name}'의 호스트 '{proxy.Host}' 주소 조회가 10초 안에 끝나지 않았습니다. DNS(인터넷) 연결을 확인하세요.");
                }
                var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault()
                    ?? throw new IOException($"프록시 서버 '{proxy.Name}'의 호스트 '{proxy.Host}'를 찾을 수 없습니다. 서버 설정의 호스트를 확인하세요.");
                servers.Add(proxy.Id, new IPEndPoint(address, proxy.Port));
            }
            var state = new Session(plan, servers);
            try
            {
                state.Listener4.ExclusiveAddressUse = true;
                state.Listener4.Server.ReceiveBufferSize = 262144; state.Listener4.Server.SendBufferSize = 262144;
                state.Listener4.Start(512);
                state.Port4 = ((IPEndPoint)state.Listener4.LocalEndpoint).Port;
                if (state.Listener6 is not null)
                {
                    state.Listener6.Server.DualMode = false; state.Listener6.ExclusiveAddressUse = true;
                    state.Listener6.Server.ReceiveBufferSize = 262144; state.Listener6.Server.SendBufferSize = 262144;
                    state.Listener6.Start(512);
                    state.Port6 = ((IPEndPoint)state.Listener6.LocalEndpoint).Port;
                }
                else state.Port6 = state.Port4;
                var filter = plan.Filter(state.Port4, state.Port6);
                WinDivertNative.ValidateFilter(filter);
                state.Handle = WinDivertNative.Open(filter);
                session = state;
                // 호출자가 WPF UI 스레드여도 중계 루프가 디스패처에 묶이지 않도록 스레드 풀에서 시작한다.
                state.Accept4 = Task.Run(() => Accept(state, state.Listener4));
                if (state.Listener6 is { } listener6) state.Accept6 = Task.Run(() => Accept(state, listener6));
                state.Capture = Task.Factory.StartNew(() => Capture(state), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                state.Maintenance = Task.Run(() => Maintain(state));
                Log?.Invoke("규칙 적용 시작. PROXY는 지금부터 새로 맺는 연결에만 적용됩니다(이미 열린 연결은 그대로).");
            }
            catch
            {
                state.Listener4.Stop(); state.Listener6?.Stop(); state.Handle?.Dispose(); state.Stop.Dispose(); state.TcpSlots.Dispose();
                session = null; throw;
            }
        }
        finally { gate.Release(); }
    }

    private void Failure(Session state, Exception ex)
    {
        Interlocked.Increment(ref state.Errors);
        var now = Environment.TickCount64;
        if (now - Interlocked.Read(ref state.LastLog) < 1000) return;
        Interlocked.Exchange(ref state.LastLog, now);
        // Only typed error summaries: upstream bodies and authentication bytes are never logged.
        Log?.Invoke(RelayDiagnostics.Describe(ex));
    }

    private async Task Accept(Session state, TcpListener listener)
    {
        var failures = 0;
        while (!state.Stop.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(state.Stop.Token).ConfigureAwait(false); }
            catch (Exception ex) when (state.Stop.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException) { return; }
            catch (SocketException ex) when (++failures <= 32)
            {
                // 큐에 있던 연결이 accept 전에 RST되는 등 연결 단위 오류는 그 연결만 버리고 계속 받는다.
                // 연속 실패가 이어지면 리스너 자체 문제로 보고 아래 catch에서 엔진을 멈춘다.
                Failure(state, ex);
                if (ex.SocketErrorCode is SocketError.NoBufferSpaceAvailable or SocketError.TooManyOpenSockets)
                {
                    try { await Task.Delay(100, state.Stop.Token).ConfigureAwait(false); } catch (OperationCanceledException) { return; }
                }
                continue;
            }
            catch (Exception ex) { Failure(state, ex); _ = StopAfterFailure(state); return; }
            failures = 0;
            try
            {
                client.NoDelay = true;
                ProxyConnector.EnableKeepAlive(client.Client);
                var flow = state.Flows.Accept((IPEndPoint)client.Client.RemoteEndPoint!, (IPEndPoint)client.Client.LocalEndPoint!);
                if (flow is null || !state.TcpSlots.Wait(0))
                {
                    if (flow is not null) state.Flows.MarkClosed(flow);
                    client.Dispose(); Interlocked.Increment(ref state.Dropped); continue;
                }
                var work = RelayTcp(state, flow, client);
                if (state.Tcp.TryAdd(flow.VirtualPort, work)) Interlocked.Increment(ref state.TcpCount);
                else state.Tcp[flow.VirtualPort] = work;
                // 가상 포트가 재할당된 뒤 옛 작업의 정리가 새 항목을 지우지 않도록 값까지 비교해 제거한다.
                _ = work.ContinueWith(_ =>
                {
                    if (state.Tcp.TryRemove(new KeyValuePair<int, Task>(flow.VirtualPort, work))) Interlocked.Decrement(ref state.TcpCount);
                }, TaskScheduler.Default);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                // accept 직후 상대가 끊어 소켓 설정·엔드포인트 조회가 실패한 경우: 이 연결만 정리한다.
                client.Dispose(); Interlocked.Increment(ref state.Dropped);
                if (!state.Stop.IsCancellationRequested) Failure(state, ex);
            }
        }
    }

    private async Task RelayTcp(Session state, TcpFlow flow, TcpClient client)
    {
        using (client)
        {
            try
            {
                using var proxy = await ProxyConnector.OpenAsync(flow.Route.Proxy!, state.Servers[flow.Route.Proxy!.Id],
                    new IPEndPoint(flow.Key.RemoteAddress, flow.Key.RemotePort), state.Bypass, state.Stop.Token).ConfigureAwait(false);
                await ProxyConnector.RelayAsync(client, proxy, state.Count, state.Stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (!state.Stop.IsCancellationRequested) Failure(state, ex);
                try { client.Client.LingerState = new LingerOption(true, 0); } catch (SocketException) { }
            }
            finally { state.Flows.MarkClosed(flow); state.TcpSlots.Release(); }
        }
    }

    private unsafe void Capture(Session state)
    {
        var bytes = new byte[WinDivertNative.BufferSize];
        var addresses = new DivertAddress[WinDivertNative.BatchSize];
        var sending = new DivertAddress[WinDivertNative.BatchSize];
        var lengths = new int[WinDivertNative.BatchSize];
        var reinjectFailures = 0;
        try
        {
            fixed (byte* pointer = bytes)
            {
                while (true)
                {
                    uint addressLength = (uint)(addresses.Length * 80);
                    if (!WinDivertNative.WinDivertRecvEx(state.Handle!, pointer, (uint)bytes.Length, out var length, 0, addresses, ref addressLength, IntPtr.Zero))
                    {
                        var error = Marshal.GetLastWin32Error();
                        if (state.Stopping && error is 232 or 995 or 6) break;
                        throw new Win32Exception(error);
                    }
                    var offset = 0; var write = 0; var count = 0;
                    for (var i = 0; i < addressLength / 80 && offset < length; i++)
                    {
                        var remaining = bytes.AsSpan(offset, (int)length - offset);
                        if (!IpPacket.TryParse(remaining, out var packet))
                        {
                            // 해석할 수 없는 패킷 하나 때문에 배치의 나머지 정상 패킷까지 재주입되지 않고
                            // 사라지지 않도록, 길이를 알 수 있으면 그 패킷만 버리고 다음 패킷으로 넘어간다.
                            Interlocked.Increment(ref state.Dropped);
                            if (!IpPacket.TryGetFrameLength(remaining, out var skipped)) break;
                            offset += skipped; continue;
                        }
                        var frame = remaining[..packet.Length]; var address = addresses[i];
                        var decision = ProcessPacket(state, packet, frame, ref address);
                        if (decision == 2 && !WinDivertNative.WinDivertHelperCalcChecksums(pointer + offset, (uint)packet.Length, ref address, 0))
                        {
                            // 체크섬 계산에 실패한 패킷만 버린다(엔진 전체를 멈추지 않음).
                            Interlocked.Increment(ref state.Dropped);
                            Failure(state, new IOException("패킷 체크섬 계산에 실패해 해당 패킷을 버렸습니다."));
                            decision = 0;
                        }
                        if (decision != 0)
                        {
                            frame.CopyTo(bytes.AsSpan(write)); lengths[count] = packet.Length; write += packet.Length; sending[count++] = address;
                        }
                        offset += packet.Length;
                    }
                    if (count > 0 && !Reinject(state, pointer, write, sending, lengths, count, ref reinjectFailures))
                        throw new IOException("패킷 재주입이 계속 실패해 규칙 적용을 중지했습니다.");
                }
            }
        }
        catch (Exception ex) { if (!state.Stopping) { Failure(state, ex); _ = StopAfterFailure(state); } }
    }

    // 배치 재주입이 실패하면 아직 나가지 않은 패킷만 하나씩 다시 보내고, 그래도 실패한 패킷만 버린다.
    // 연속된 배치에서 한 패킷도 보내지 못할 때만 false를 돌려 엔진을 멈춘다.
    private unsafe bool Reinject(Session state, byte* pointer, int write, DivertAddress[] sending, int[] lengths, int count, ref int consecutiveFailures)
    {
        if (WinDivertNative.WinDivertSendEx(state.Handle!, pointer, (uint)write, out var sent, 0, sending, (uint)(count * 80), IntPtr.Zero) && sent == write)
        {
            consecutiveFailures = 0; return true;
        }
        var error = Marshal.GetLastWin32Error();
        var offset = 0; var delivered = 0;
        for (var i = 0; i < count; i++)
        {
            var size = lengths[i];
            // 배치 앞부분이 이미 나갔다면(sent 바이트) 중복으로 보내지 않는다.
            if (offset + size <= sent) { offset += size; delivered++; continue; }
            var address = sending[i];
            if (WinDivertNative.WinDivertSend(state.Handle!, pointer + offset, (uint)size, out var one, ref address) && one == size) delivered++;
            else Interlocked.Increment(ref state.Dropped);
            offset += size;
        }
        if (delivered < count) Failure(state, new Win32Exception(error));
        consecutiveFailures = delivered == 0 ? consecutiveFailures + 1 : 0;
        return consecutiveFailures < ReinjectFailureLimit;
    }

    // 0: consumed/dropped; 1: pass untouched; 2: translated, checksum required.
    private int ProcessPacket(Session state, IpPacket packet, Span<byte> bytes, ref DivertAddress address)
    {
        if (packet.Fragmented)
        {
            // 조각은 포트·프로세스를 알 수 없으므로 목적지·프로토콜만으로 확정되는 판정만 따른다.
            switch (state.Plan.ClassifyFragment(packet.Destination, packet.Protocol))
            {
                case FragmentDecision.Pass: return 1;
                case FragmentDecision.Block: Interlocked.Increment(ref state.Blocked); return 0;
                default: Interlocked.Increment(ref state.Dropped); return 0;
            }
        }
        var key = packet.Key(bytes);
        var ipv4 = packet.Source.AddressFamily == AddressFamily.InterNetwork;
        // 리스너는 IPv4/IPv6 전용으로 따로 바인드되므로 같은 계열의 포트만 리스너 응답으로 본다.
        if (packet.Tcp && key.LocalPort == (ipv4 ? state.Port4 : state.Port6))
        {
            var flow = state.Flows.FindVirtual(key.RemotePort);
            // 리스너는 가상 연결만 받는다. 대응 흐름이 없는 응답(회수된 흐름의 FIN/RST 재전송 등)을
            // 그대로 내보내면 리스너 포트·가상 포트로 된 패킷이 실제 원격지로 나가므로 버린다.
            if (flow is null || !key.RemoteAddress.Equals(flow.Key.RemoteAddress) || !key.LocalAddress.Equals(flow.Key.LocalAddress))
            {
                Interlocked.Increment(ref state.Dropped); return 0;
            }
            packet.Rewrite(bytes, flow.Key.RemoteAddress, flow.Key.RemotePort, flow.Key.LocalAddress, flow.Key.LocalPort);
            address.Inbound(); return 2;
        }
        var family = ipv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
        if (state.Bypass.Contains(key.Udp, family, key.LocalPort)) return 1;
        var now = Environment.TickCount64;
        var syn = packet.Tcp && (bytes[packet.TransportOffset + 13] & 0x12) == 0x02;
        if (packet.Tcp && state.Flows.Find(key) is { } existing)
        {
            if (!syn || existing.Sequence == BinaryPrimitives.ReadUInt32BigEndian(bytes[(packet.TransportOffset + 4)..]))
            {
                Volatile.Write(ref existing.LastSeen, now);
                packet.Rewrite(bytes, key.RemoteAddress, existing.VirtualPort, key.LocalAddress, ipv4 ? state.Port4 : state.Port6);
                address.Inbound(); return 2;
            }
            // 같은 4-튜플로 시작된 새 연결(시퀀스가 다른 SYN): 옛 프록시 흐름이 이 연결의 후속 패킷을
            // 리스너로 끌고 가지 않도록 원래 주소 매핑을 끊고 아래에서 새로 판정한다.
            state.Flows.Forget(key, existing);
        }
        if (packet.Udp && state.Udp.TryGetValue(key, out var association))
        {
            if (association.Completion.IsCompleted)
            {
                // 프록시 오류 등으로 끝난 association은 1초 동안만 폐기(재연결 폭주 방지)하고, 이후엔 치우고 새로 판정한다.
                if (now - Volatile.Read(ref association.Finished) < 1000) { Interlocked.Increment(ref state.Dropped); return 0; }
                Forget(state, key, association);
            }
            else if (!association.CheckOwner || now - Volatile.Read(ref association.OwnerChecked) < OwnerRecheck)
            {
                if (!association.Enqueue(bytes[packet.PayloadOffset..])) Interlocked.Increment(ref state.Dropped);
                return 0;
            }
            else
            {
                // 프로세스 조건으로 만든 association만, 유휴 중 다른 프로세스가 포트를 재사용했는지 주기적으로 확인한다.
                var currentName = SocketOwners.Name(SocketOwners.Find(key));
                if (currentName is null)
                {
                    // 조회 실패 때 패킷마다 소켓 테이블을 다시 읽지 않도록 잠시 뒤에만 재시도한다.
                    Volatile.Write(ref association.OwnerChecked, now - OwnerRecheck + OwnerRetry);
                    Interlocked.Increment(ref state.Dropped);
                    Failure(state, new ConnectionOwnerException());
                    return 0;
                }
                Volatile.Write(ref association.OwnerChecked, now);
                var currentRoute = state.Plan.Match(key.RemoteAddress, key.RemotePort, true, currentName);
                if (currentRoute?.Action == RuleAction.Proxy && currentRoute.Proxy?.Id == association.ProxyId)
                {
                    if (!association.Enqueue(bytes[packet.PayloadOffset..])) Interlocked.Increment(ref state.Dropped);
                    return 0;
                }
                // 경로가 바뀌면 사전에서도 제거하고 아래 일반 판정으로 다시 처리한다.
                Forget(state, key, association);
            }
        }
        if (!syn && state.Passthrough.TryGetValue(key, out var decided))
        {
            // TCP: 이미 직접 통과로 판정된 연결. UDP: 포트 재사용에 대비해 짧은 시간만 판정을 재사용한다.
            if (packet.Tcp) { state.Passthrough.TryUpdate(key, now, decided); return 1; }
            if (now - decided < UdpDecisionLifetime) return 1;
        }
        var firstIndex = state.Plan.FirstIndex(key.RemoteAddress, key.RemotePort, key.Udp);
        var firstCandidate = firstIndex >= 0 ? state.Plan.Entries[firstIndex] : null;
        if (firstCandidate is { Action: RuleAction.Direct } && firstCandidate.Program.Length == 0)
        {
            // An unconditional first DIRECT rule must not depend on later process rules
            // or on whether a short-lived socket's owner can still be queried.
            Remember(state, key, now);
            return 1;
        }
        var needsOwner = firstCandidate?.Program.Length > 0;
        var localProxyPids = state.LocalProxies.Current();
        var owner = needsOwner || localProxyPids.Count > 0 ? SocketOwners.Find(key) : null;
        var excluded = owner is { } pid && (pid == Environment.ProcessId || localProxyPids.Contains(pid));
        // 프로세스 조건 판정에는 이름이 필요하다. PID는 찾았지만 이름 조회가 실패하면(종료·접근 거부)
        // 소유자 조회 실패와 같이 취급해 규칙을 우회하지 않는다.
        var name = needsOwner && owner is not null && !excluded ? SocketOwners.Name(owner) : null;
        // If a local proxy exists but attribution fails, do not risk recursively redirecting it.
        var unknownLocal = localProxyPids.Count > 0 && owner is null;
        if (unknownLocal || (needsOwner && !excluded && name is null))
        {
            // 이미 시작된 TCP 연결(비-SYN)은 어차피 프록시로 돌릴 수 없으므로 소유자를 몰라도 통과시킨다.
            if (packet.Tcp && !syn) { Remember(state, key, now); return 1; }
            Interlocked.Increment(ref state.Dropped);
            Failure(state, new ConnectionOwnerException());
            return 0;
        }
        // 앞쪽 규칙은 이미 주소·포트·프로토콜에서 맞지 않았으므로 첫 후보 위치부터 이어서 찾는다.
        var route = excluded ? null : state.Plan.Match(key.RemoteAddress, key.RemotePort, key.Udp, name, firstIndex);
        if (route?.Action == RuleAction.Block)
        {
            Interlocked.Increment(ref state.Blocked);
            return 0;
        }
        if (route is null || route.Action == RuleAction.Direct || (packet.Tcp && !syn))
        {
            Remember(state, key, now);
            return 1;
        }
        // 중지 중에는 새 프록시 흐름·UDP association 생성만 막고, 통과·차단 판정은 그대로 처리한다.
        if (state.Stopping) { Interlocked.Increment(ref state.Dropped); return 0; }
        if (packet.Tcp)
        {
            var flow = state.Flows.Create(key, route, BinaryPrimitives.ReadUInt32BigEndian(bytes[(packet.TransportOffset + 4)..]), state.Port4, state.Port6);
            if (flow is null) { Interlocked.Increment(ref state.Dropped); return 0; }
            packet.Rewrite(bytes, key.RemoteAddress, flow.VirtualPort, key.LocalAddress, ipv4 ? state.Port4 : state.Port6);
            address.Inbound(); return 2;
        }
        if (Interlocked.Read(ref state.UdpCount) >= 512) { Interlocked.Increment(ref state.Dropped); return 0; }
        var replyAddress = address; replyAddress.Inbound();
        var udp = new UdpAssociation(key, route.Proxy!, state.Servers[route.Proxy!.Id], state.Bypass, state.Budget,
            reply => SendUdpReply(state, reply, replyAddress), state.Count, ex => Failure(state, ex), state.Stop.Token) { CheckOwner = needsOwner };
        if (!state.Udp.TryAdd(key, udp)) { udp.Dispose(); Interlocked.Increment(ref state.Dropped); return 0; }
        Interlocked.Increment(ref state.UdpCount);
        if (!udp.Enqueue(bytes[packet.PayloadOffset..])) Interlocked.Increment(ref state.Dropped);
        return 0;
    }

    private void Remember(Session state, FlowKey key, long now)
    {
        if (state.Passthrough.TryAdd(key, now))
        {
            if (Interlocked.Increment(ref state.PassthroughCount) > PassthroughCapacity) TrimPassthrough(state);
        }
        else if (state.Passthrough.TryGetValue(key, out var old)) state.Passthrough.TryUpdate(key, now, old);
    }

    // 상한을 넘으면 새 판정을 버리지 않고 가장 오래 쓰이지 않은 항목부터 1/8을 비운다.
    // (저장을 건너뛰면 그 흐름의 패킷마다 규칙·소유자 판정이 반복된다.)
    private void TrimPassthrough(Session state)
    {
        foreach (var pair in state.Passthrough.OrderBy(p => p.Value).Take(PassthroughCapacity / 8).ToArray())
            if (state.Passthrough.TryRemove(pair)) Interlocked.Decrement(ref state.PassthroughCount);
        if (Interlocked.Exchange(ref state.PassthroughTrimmed, 1) == 0)
            Log?.Invoke($"직접 통과 연결이 많아 판정 캐시({PassthroughCapacity}개)가 가득 찼습니다. 오래된 항목부터 정리합니다.");
    }

    private static void Forget(Session state, FlowKey key, UdpAssociation association)
    {
        if (state.Udp.TryRemove(new KeyValuePair<FlowKey, UdpAssociation>(key, association))) Interlocked.Decrement(ref state.UdpCount);
        association.Dispose();
    }

    private static unsafe void SendUdpReply(Session state, byte[] bytes, DivertAddress address)
    {
        fixed (byte* packet = bytes)
        {
            if (!WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)bytes.Length, ref address, 0)
                || !WinDivertNative.WinDivertSend(state.Handle!, packet, (uint)bytes.Length, out var sent, ref address) || sent != bytes.Length)
                throw new IOException("UDP reply injection failed.");
        }
    }

    private async Task Maintain(Session state)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (await timer.WaitForNextTickAsync(state.Stop.Token).ConfigureAwait(false))
            {
                try
                {
                    state.Flows.Sweep(); var now = Environment.TickCount64;
                    foreach (var pair in state.Passthrough.Where(p => now - p.Value > (p.Key.Udp ? UdpDecisionLifetime : PassthroughLifetime)))
                        if (state.Passthrough.TryRemove(pair)) Interlocked.Decrement(ref state.PassthroughCount);
                    foreach (var pair in state.Udp.Where(p => p.Value.Completion.IsCompleted || now - Volatile.Read(ref p.Value.LastSeen) > 120000))
                    {
                        if (!state.Udp.TryRemove(pair)) continue;
                        Interlocked.Decrement(ref state.UdpCount);
                        pair.Value.Dispose();
                        await Settle(state, pair.Value.Completion).ConfigureAwait(false);
                    }
                }
                // 한 번의 정리 실패로 유지보수 루프가 영구 종료되면 흐름 표가 상한에 차 새 연결이 모두 막힌다.
                catch (Exception ex) when (ex is not OperationCanceledException) { Failure(state, ex); }
            }
        }
        catch (OperationCanceledException) { }
    }

    private async Task Settle(Session state, Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch (Exception ex) { if (ex is not OperationCanceledException && !state.Stopping) Failure(state, ex); }
    }

    private async Task StopAfterFailure(Session failed)
    {
        // Wait until the capture callback returns before StopAsync joins its worker.
        await Task.Yield();
        // 세션 비교와 정지를 같은 gate 안에서 해, 그 사이 새로 시작된 세션을 대신 멈추지 않게 한다.
        if (await StopCoreAsync(failed).ConfigureAwait(false)) Exited?.Invoke();
    }

    public Task StopAsync() => StopCoreAsync(null);

    private async Task<bool> StopCoreAsync(Session? expected)
    {
        await gate.WaitAsync();
        try
        {
            var state = session;
            if (state is null || (expected is not null && !ReferenceEquals(state, expected))) return false;
            state.Stopping = true; state.Stop.Cancel(); state.Listener4.Stop(); state.Listener6?.Stop();
            try
            {
                // 하나가 실패해도 TCP 중계·UDP 대기를 건너뛴 채 자원을 해제하지 않도록 각각 기다린다.
                await Settle(state, state.Accept4).ConfigureAwait(false);
                await Settle(state, state.Accept6).ConfigureAwait(false);
                await Settle(state, state.Maintenance).ConfigureAwait(false);
                foreach (var flow in state.Udp.Values) flow.Dispose();
                foreach (var task in state.Tcp.Values.Concat(state.Udp.Values.Select(f => f.Completion)).ToArray())
                    await Settle(state, task).ConfigureAwait(false);
            }
            finally
            {
                if (!WinDivertNative.WinDivertShutdown(state.Handle!, WinDivertNative.ShutdownReceive)) state.Handle!.Abort();
                await state.Capture;
                state.Handle!.Dispose(); state.Stop.Dispose(); state.TcpSlots.Dispose();
                last = state.Statistics with { TcpConnections = 0, UdpAssociations = 0 }; session = null;
                Log?.Invoke("규칙 적용 중지. 패킷 캡처를 해제했습니다.");
            }
            return true;
        }
        finally { gate.Release(); }
    }
    public async ValueTask DisposeAsync() { await StopAsync(); gate.Dispose(); }
}
