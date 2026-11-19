using System.Net.Sockets;
using ProxyWin.Core;

namespace ProxyWin.Windows;

internal sealed class HttpConnectException(int? status) : IOException(status is { } code
    ? $"HTTP {code}: " + (code switch
    {
        407 => "프록시 인증이 필요하거나 거부되었습니다. 서버의 사용자명/비밀번호를 확인하세요.",
        401 => "인증이 거부되었습니다. HTTP 프록시 리스너가 맞는지 확인하세요.",
        403 => "프록시가 이 CONNECT 대상을 거부했습니다. 프록시의 허용 규칙/포트를 확인하세요.",
        405 => "이 리스너는 CONNECT를 지원하지 않습니다.",
        502 or 503 or 504 => "프록시가 목적지에 연결하지 못했습니다. 프록시 쪽 이벤트 로그를 확인하세요.",
        _ => "프록시가 HTTP CONNECT 요청을 거부했습니다."
    }) : "HTTP CONNECT 응답이 올바르지 않거나 너무 깁니다. 서버 종류(HTTP/SOCKS5)와 포트를 확인하세요.");

// 앱이 직접 정의한 문구만 담는다(서버 응답 원문·인증 정보는 넣지 않음).
internal sealed class Socks5Exception(string message) : IOException(message)
{
    internal static string Reply(byte status) => $"SOCKS5 서버가 연결을 거부했습니다(코드 {status}: " + (status switch
    {
        1 => "서버 일반 오류",
        2 => "서버 규칙상 허용되지 않음",
        3 => "네트워크에 도달할 수 없음",
        4 => "호스트에 도달할 수 없음",
        5 => "목적지가 연결을 거부함",
        6 => "TTL 만료",
        7 => "지원하지 않는 명령(UDP 미지원 서버일 수 있음)",
        8 => "지원하지 않는 주소 형식",
        _ => "알 수 없는 응답"
    }) + ").";
}

internal sealed class ProxyHandshakeException(ProxyKind kind, Exception inner)
    : IOException($"{(kind == ProxyKind.Http ? "HTTP CONNECT" : "SOCKS5")} 핸드셰이크 실패: {RelayDiagnostics.Describe(inner)}", inner);

internal sealed class ConnectionOwnerException() : IOException("연결의 소유 프로세스를 확인할 수 없어 패킷을 폐기했습니다(프로세스 조건 판정 또는 로컬 프록시 루프 방지에 필요).");

internal static class RelayDiagnostics
{
    // Only our typed protocol messages and numeric socket/HRESULT codes are safe.
    // Never log arbitrary Exception.Message, response headers/bodies or credentials.
    internal static string Describe(Exception error) => error switch
    {
        ProxyHandshakeException handshake => handshake.Message,
        HttpConnectException http => http.Message,
        Socks5Exception socks => socks.Message,
        ConnectionOwnerException owner => owner.Message,
        SocketException socket => $"소켓 오류 {socket.SocketErrorCode} ({socket.NativeErrorCode}).{Hint(socket.SocketErrorCode)}",
        System.ComponentModel.Win32Exception native => $"중계/캡처 중 Windows 오류 {native.NativeErrorCode}.",
        IOException { InnerException: SocketException socket } => $"TCP 스트림: 소켓 {socket.SocketErrorCode} ({socket.NativeErrorCode}).",
        EndOfStreamException => "응답이 끝나기 전에 상대가 연결을 닫았습니다. 서버 종류(HTTP/SOCKS5)와 포트를 확인하세요.",
        OperationCanceledException => "작업이 취소되었거나 시간 초과되었습니다.",
        IOException io => $"I/O 오류 (HRESULT 0x{io.HResult:X8}).",
        _ => $"중계 오류: {error.GetType().Name}."
    };

    private static string Hint(SocketError error) => error switch
    {
        SocketError.ConnectionRefused => " 프록시 서버가 꺼져 있거나 포트가 다릅니다(127.0.0.1이면 이 PC에서 실행 중이어야 함).",
        SocketError.TimedOut => " 프록시 서버에 응답이 없습니다. 주소와 방화벽을 확인하세요.",
        SocketError.HostUnreachable or SocketError.NetworkUnreachable => " 프록시 서버 주소에 도달할 수 없습니다.",
        _ => ""
    };
}
