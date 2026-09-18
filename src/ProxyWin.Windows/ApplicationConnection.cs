using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace ProxyWin.Windows;

internal static class ApplicationConnection
{
    internal static readonly SocketBypass Bypass = new();

    internal static ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken token) =>
        ConnectAsync(context.DnsEndPoint, token);

    internal static async ValueTask<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        // The dual-mode wildcard bind reserves this TCP port for our socket in
        // both address families. Register before Connect emits the first SYN.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true, ExclusiveAddressUse = true };
        IDisposable? lease = null;
        try
        {
            socket.Bind(new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            lease = Bypass.Register(false, ((IPEndPoint)socket.LocalEndPoint!).Port);
            await socket.ConnectAsync(endpoint, token).ConfigureAwait(false);
            return new OwnedStream(socket, lease);
        }
        catch { socket.Dispose(); lease?.Dispose(); throw; }
    }

    private sealed class OwnedStream : NetworkStream
    {
        private IDisposable? lease;
        internal OwnedStream(Socket socket, IDisposable lease) : base(socket, ownsSocket: true) { this.lease = lease; }
        protected override void Dispose(bool disposing)
        {
            try { base.Dispose(disposing); }
            finally { Interlocked.Exchange(ref lease, null)?.Dispose(); }
        }
        public override async ValueTask DisposeAsync()
        {
            try { await base.DisposeAsync().ConfigureAwait(false); }
            finally { Interlocked.Exchange(ref lease, null)?.Dispose(); }
        }
    }
}
