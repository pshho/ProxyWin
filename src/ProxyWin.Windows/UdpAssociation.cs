using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using ProxyWin.Core;

namespace ProxyWin.Windows;

internal sealed class DatagramBudget
{
    private long queued;
    public bool TryReserve(int size)
    {
        if (Interlocked.Add(ref queued, size) <= 16 * 1024 * 1024) return true;
        Interlocked.Add(ref queued, -size); return false;
    }
    public void Release(int size) => Interlocked.Add(ref queued, -size);
}

internal sealed class UdpAssociation : IDisposable
{
    // 큐에는 SOCKS5 UDP 헤더까지 붙인 송신 형태의 풀 버퍼를 넣어, 전송할 때 다시 복사하지 않는다.
    private readonly Channel<(byte[] Buffer, int Length)> queue = Channel.CreateBounded<(byte[] Buffer, int Length)>(new BoundedChannelOptions(32) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    // SOCKS5 UDP 헤더(RSV·FRAG·원래 목적지)는 흐름마다 고정이라 한 번만 만든다.
    private readonly byte[] prefix;
    private readonly CancellationTokenSource stop;
    private readonly DatagramBudget budget;
    private int disposed;
    public long LastSeen = Environment.TickCount64;
    // 프로세스 규칙 재검사 시각(패킷마다 소켓 테이블을 읽지 않도록 TTL 판단에 사용)
    public long OwnerChecked = Environment.TickCount64;
    // 종료 시각. 실패한 association을 곧바로 재생성해 프록시에 연결 폭주를 일으키지 않도록 쓴다.
    public long Finished;
    // 프로세스 조건 규칙으로 만든 association만 소유 프로세스를 주기적으로 다시 확인한다.
    public bool CheckOwner { get; init; }
    public string ProxyId { get; }
    public Task Completion { get; }

    public UdpAssociation(FlowKey flow, ProxyServer proxy, IPEndPoint server, SocketBypass bypass, DatagramBudget budget,
        Action<byte[]> received, Action<int, bool> count, Action<Exception> failed, CancellationToken token)
    {
        this.budget = budget; ProxyId = proxy.Id; stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        prefix = new byte[] { 0, 0, 0 }.Concat(ProxyConnector.EncodeAddress(new IPEndPoint(flow.RemoteAddress, flow.RemotePort))).ToArray();
        Completion = Run(flow, proxy, server, bypass, received, count, failed);
    }
    public bool Enqueue(ReadOnlySpan<byte> payload)
    {
        Volatile.Write(ref LastSeen, Environment.TickCount64);
        if (stop.IsCancellationRequested || !budget.TryReserve(payload.Length)) return false;
        var length = prefix.Length + payload.Length;
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        prefix.CopyTo(buffer, 0); payload.CopyTo(buffer.AsSpan(prefix.Length));
        if (queue.Writer.TryWrite((buffer, length))) return true;
        ArrayPool<byte>.Shared.Return(buffer); budget.Release(payload.Length); return false;
    }
    private async Task Run(FlowKey flow, ProxyServer proxy, IPEndPoint server, SocketBypass bypass,
        Action<byte[]> received, Action<int, bool> count, Action<Exception> failed)
    {
        try
        {
            using var control = await ProxyConnector.OpenAsync(proxy, server, new IPEndPoint(flow.RemoteAddress, flow.RemotePort), bypass, stop.Token, udpAssociate: true);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var udp = new UdpClient(server.AddressFamily) { ExclusiveAddressUse = true };
            udp.Client.Bind(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0));
            using var lease = bypass.Register(true, server.AddressFamily, ((IPEndPoint)udp.Client.LocalEndPoint!).Port);
            var any = new IPEndPoint(server.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            var bound = await ProxyConnector.SocksCommandAsync(control.Stream, 3, any, timeout.Token);
            if (bound.Port == 0) throw new Socks5Exception("SOCKS5 서버가 UDP 중계 포트를 주지 않았습니다(UDP 미지원 서버일 수 있음).");
            var addresses = await Dns.GetHostAddressesAsync(bound.Host, timeout.Token);
            var relay = addresses.FirstOrDefault(a => a.AddressFamily == server.AddressFamily) ?? throw new Socks5Exception("SOCKS5 UDP 중계 주소의 IP 계열이 프록시 서버와 다릅니다.");
            if (relay.Equals(IPAddress.Any) || relay.Equals(IPAddress.IPv6Any)) relay = server.Address;
            udp.Connect(new IPEndPoint(relay, bound.Port));
            async Task Send()
            {
                await foreach (var (buffer, length) in queue.Reader.ReadAllAsync(stop.Token))
                {
                    var payloadLength = length - prefix.Length;
                    try
                    {
                        if (length > IpPacket.MaxUdpPayload(server.AddressFamily == AddressFamily.InterNetwork)) { failed(new Socks5Exception("UDP 데이터그램이 SOCKS5 중계 한도보다 커서 버렸습니다.")); continue; }
                        await udp.SendAsync(buffer.AsMemory(0, length), stop.Token); count(payloadLength, true);
                    }
                    finally { budget.Release(payloadLength); ArrayPool<byte>.Shared.Return(buffer); }
                }
            }
            async Task Receive()
            {
                // 수신 버퍼는 association마다 하나를 재사용하고, 출발지 확인도 객체를 만들지 않고 한다.
                var buffer = new byte[65536];
                while (!stop.IsCancellationRequested)
                {
                    var size = await udp.Client.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, stop.Token);
                    if (!ProxyConnector.TryMatchDatagram(buffer.AsSpan(0, size), flow.RemoteAddress, flow.RemotePort, out var offset)) continue;
                    Volatile.Write(ref LastSeen, Environment.TickCount64);
                    if (stop.IsCancellationRequested) return;
                    // 앱 쪽 주소 계열로 다시 만들 수 없는 크기의 응답은 이 데이터그램만 버린다.
                    if (size - offset > IpPacket.MaxUdpPayload(flow.LocalAddress.AddressFamily == AddressFamily.InterNetwork))
                    {
                        failed(new Socks5Exception("SOCKS5 UDP 응답이 너무 커서 버렸습니다."));
                        continue;
                    }
                    received(IpPacket.UdpReply(flow, buffer.AsSpan(offset, size - offset)));
                    count(size - offset, false);
                }
            }
            async Task WatchControl()
            {
                var buffer = new byte[1];
                while (await control.Stream.ReadAsync(buffer, stop.Token) != 0) { }
                throw new Socks5Exception("SOCKS5 UDP 제어 연결이 닫혔습니다.");
            }
            var tasks = new[] { Send(), Receive(), WatchControl() };
            var completed = await Task.WhenAny(tasks);
            if (completed.IsFaulted && !stop.IsCancellationRequested) failed(completed.Exception!.GetBaseException());
            stop.Cancel();
            await Task.WhenAll(tasks);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            if (!stop.IsCancellationRequested) failed(ex);
        }
        catch (Exception ex)
        {
            // Completion이 fault되면 엔진 유지보수 루프가 멈추므로 예상 밖 예외도 여기서 끝낸다.
            failed(ex);
        }
        finally
        {
            Volatile.Write(ref Finished, Environment.TickCount64);
            stop.Cancel(); queue.Writer.TryComplete();
            while (queue.Reader.TryRead(out var remaining)) { budget.Release(remaining.Length - prefix.Length); ArrayPool<byte>.Shared.Return(remaining.Buffer); }
        }
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); queue.Writer.TryComplete();
        _ = Completion.ContinueWith(_ => stop.Dispose(), TaskScheduler.Default);
    }
}
