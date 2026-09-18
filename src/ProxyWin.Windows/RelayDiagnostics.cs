using System.Net.Sockets;
using ProxyWin.Core;

namespace ProxyWin.Windows;

internal sealed class HttpConnectException(int? status) : IOException(status is { } code
    ? $"HTTP {code}: " + (code switch
    {
        407 => "proxy authentication required or rejected.",
        401 => "authentication rejected; verify this is an HTTP proxy listener.",
        403 => "CONNECT destination denied by the proxy.",
        405 => "CONNECT is not supported on this listener.",
        502 or 503 or 504 => "proxy could not establish the destination connection.",
        _ => "HTTP CONNECT rejected by the proxy."
    }) : "Invalid or oversized HTTP CONNECT response. Check the proxy type and listener port.");

internal sealed class ProxyHandshakeException(ProxyKind kind, Exception inner)
    : IOException($"{(kind == ProxyKind.Http ? "HTTP CONNECT" : "SOCKS5")} handshake: {RelayDiagnostics.Describe(inner)}", inner);

internal sealed class ConnectionOwnerException() : IOException("Cannot identify the connection owner. Packet dropped because process attribution is required.");

internal static class RelayDiagnostics
{
    // Only our typed protocol messages and numeric socket/HRESULT codes are safe.
    // Never log arbitrary Exception.Message, response headers/bodies or credentials.
    internal static string Describe(Exception error) => error switch
    {
        ProxyHandshakeException handshake => handshake.Message,
        HttpConnectException http => http.Message,
        ConnectionOwnerException owner => owner.Message,
        SocketException socket => $"Socket {socket.SocketErrorCode} ({socket.NativeErrorCode}).",
        System.ComponentModel.Win32Exception native => $"Windows error {native.NativeErrorCode} during relay/capture.",
        IOException { InnerException: SocketException socket } => $"TCP stream: Socket {socket.SocketErrorCode} ({socket.NativeErrorCode}).",
        EndOfStreamException => "Peer closed the connection before its reply was complete.",
        OperationCanceledException => "Operation cancelled or timed out.",
        IOException io => $"I/O failure (HRESULT 0x{io.HResult:X8}).",
        _ => $"Relay error: {error.GetType().Name}."
    };
}
