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
    private readonly Channel<byte[]> queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(32) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly CancellationTokenSource stop;
    private readonly DatagramBudget budget;
    private int disposed;
    public long LastSeen = Environment.TickCount64;
    // 프로세스 규칙 재검사 시각(패킷마다 소켓 테이블을 읽지 않도록 TTL 판단에 사용)
    public long OwnerChecked = Environment.TickCount64;
    // 종료 시각. 실패한 association을 곧바로 재생성해 프록시에 연결 폭주를 일으키지 않도록 쓴다.
    public long Finished;
    public string ProxyId { get; }
    public Task Completion { get; }

    public UdpAssociation(FlowKey flow, ProxyServer proxy, IPEndPoint server, SocketBypass bypass, DatagramBudget budget,
        Action<byte[]> received, Action<int, bool> count, Action<Exception> failed, CancellationToken token)
    {
        this.budget = budget; ProxyId = proxy.Id; stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        Completion = Run(flow, proxy, server, bypass, received, count, failed);
    }
    public bool Enqueue(ReadOnlySpan<byte> payload)
    {
        Volatile.Write(ref LastSeen, Environment.TickCount64);
        if (stop.IsCancellationRequested || !budget.TryReserve(payload.Length)) return false;
        var bytes = payload.ToArray();
        if (queue.Writer.TryWrite(bytes)) return true;
        budget.Release(bytes.Length); return false;
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
            var prefix = new byte[] { 0, 0, 0 }.Concat(ProxyConnector.EncodeAddress(new IPEndPoint(flow.RemoteAddress, flow.RemotePort))).ToArray();
            async Task Send()
            {
                await foreach (var payload in queue.Reader.ReadAllAsync(stop.Token))
                {
                    try
                    {
                        if (prefix.Length + payload.Length > IpPacket.MaxUdpPayload(server.AddressFamily == AddressFamily.InterNetwork)) { failed(new Socks5Exception("UDP 데이터그램이 SOCKS5 중계 한도보다 커서 버렸습니다.")); continue; }
                        var datagram = new byte[prefix.Length + payload.Length]; prefix.CopyTo(datagram, 0); payload.CopyTo(datagram, prefix.Length);
                        await udp.SendAsync(datagram, stop.Token); count(payload.Length, true);
                    }
                    finally { budget.Release(payload.Length); }
                }
            }
            async Task Receive()
            {
                while (!stop.IsCancellationRequested)
                {
                    var datagram = await udp.ReceiveAsync(stop.Token);
                    if (!ProxyConnector.TryDecodeDatagram(datagram.Buffer, out var source, out var offset)
                        || source!.Port != flow.RemotePort || !source.Address.Equals(flow.RemoteAddress)) continue;
                    Volatile.Write(ref LastSeen, Environment.TickCount64);
                    if (stop.IsCancellationRequested) return;
                    // 앱 쪽 주소 계열로 다시 만들 수 없는 크기의 응답은 이 데이터그램만 버린다.
                    if (datagram.Buffer.Length - offset > IpPacket.MaxUdpPayload(flow.LocalAddress.AddressFamily == AddressFamily.InterNetwork))
                    {
                        failed(new Socks5Exception("SOCKS5 UDP 응답이 너무 커서 버렸습니다."));
                        continue;
                    }
                    received(IpPacket.UdpReply(flow, datagram.Buffer.AsSpan(offset)));
                    count(datagram.Buffer.Length - offset, false);
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
            while (queue.Reader.TryRead(out var remaining)) budget.Release(remaining.Length);
        }
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); queue.Writer.TryComplete();
        _ = Completion.ContinueWith(_ => stop.Dispose(), TaskScheduler.Default);
    }
}
