using System.Buffers.Binary;
using System.Net;

namespace ProxyWin.Core;

public readonly record struct FlowKey(IPAddress LocalAddress, int LocalPort, IPAddress RemoteAddress, int RemotePort, bool Udp);

public readonly record struct IpPacket(int Length, int TransportOffset, int PayloadOffset, byte Protocol, bool Fragmented, IPAddress Source, IPAddress Destination)
{
    public bool Udp => Protocol == 17;
    public bool Tcp => Protocol == 6;
    public FlowKey Key(ReadOnlySpan<byte> packet) => new(Source, BinaryPrimitives.ReadUInt16BigEndian(packet[TransportOffset..]),
        Destination, BinaryPrimitives.ReadUInt16BigEndian(packet[(TransportOffset + 2)..]), Udp);

    // 파싱에 실패한 패킷이라도 IP 헤더의 길이 필드로 프레임 경계를 알 수 있으면
    // 배치의 다음 패킷을 계속 처리할 수 있다. (IPv6 jumbogram처럼 길이를 모르면 false)
    public static bool TryGetFrameLength(ReadOnlySpan<byte> bytes, out int length)
    {
        length = 0;
        if (bytes.Length >= 20 && (bytes[0] >> 4) == 4) length = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        else if (bytes.Length >= 40 && (bytes[0] >> 4) == 6 && BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) is > 0 and var payload) length = 40 + payload;
        if (length < 20 || length > bytes.Length) { length = 0; return false; }
        return true;
    }

    // IPv4는 IP 헤더 20바이트, IPv6는 payload length(16비트)에 UDP 헤더 8바이트가 포함된다.
    public static int MaxUdpPayload(bool ipv4) => ipv4 ? 65507 : 65527;

    public static bool TryParse(ReadOnlySpan<byte> bytes, out IpPacket packet)
    {
        packet = default;
        if (bytes.Length < 20) return false;
        int length, offset; byte protocol; bool fragmented = false; IPAddress source, destination;
        if ((bytes[0] >> 4) == 4)
        {
            length = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]); offset = (bytes[0] & 15) * 4;
            if (offset < 20 || length < offset || length > bytes.Length) return false;
            protocol = bytes[9]; source = new IPAddress(bytes.Slice(12, 4)); destination = new IPAddress(bytes.Slice(16, 4));
            fragmented = (BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) & 0x3fff) != 0;
        }
        else if ((bytes[0] >> 4) == 6)
        {
            if (bytes.Length < 40) return false;
            length = 40 + BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]); offset = 40;
            if (length > bytes.Length) return false;
            protocol = bytes[6]; source = new IPAddress(bytes.Slice(8, 16)); destination = new IPAddress(bytes.Slice(24, 16));
            for (var i = 0; protocol is 0 or 43 or 60 or 44 or 51; i++)
            {
                if (i > 8 || offset + 8 > length) return false;
                var next = bytes[offset];
                var extensionLength = protocol switch { 44 => 8, 51 => (bytes[offset + 1] + 2) * 4, _ => (bytes[offset + 1] + 1) * 8 };
                if (protocol == 44) fragmented = (BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 2)..]) & 0xfff9) != 0;
                offset += extensionLength; protocol = next;
                if (offset > length || fragmented) break;
            }
        }
        else return false;
        var payload = offset;
        if (!fragmented)
        {
            if (protocol == 6)
            {
                if (offset + 20 > length) return false;
                var tcpLength = (bytes[offset + 12] >> 4) * 4;
                if (tcpLength < 20 || offset + tcpLength > length) return false;
                payload += tcpLength;
            }
            else if (protocol == 17)
            {
                if (offset + 8 > length) return false;
                var udpLength = BinaryPrimitives.ReadUInt16BigEndian(bytes[(offset + 4)..]);
                if (udpLength < 8 || offset + udpLength != length) return false;
                payload += 8;
            }
            else return false;
        }
        packet = new IpPacket(length, offset, payload, protocol, fragmented, source, destination);
        return true;
    }

    public void Rewrite(Span<byte> bytes, IPAddress source, int sourcePort, IPAddress destination, int destinationPort)
    {
        var ipv4 = (bytes[0] >> 4) == 4;
        // 패킷마다 byte[]를 만들지 않도록 주소를 패킷 버퍼에 직접 쓴다.
        if (!source.TryWriteBytes(bytes[(ipv4 ? 12 : 8)..], out var sourceLength) || sourceLength != (ipv4 ? 4 : 16)
            || !destination.TryWriteBytes(bytes[(ipv4 ? 16 : 24)..], out var destinationLength) || destinationLength != (ipv4 ? 4 : 16))
            throw new ArgumentException("Address family differs from the packet.");
        BinaryPrimitives.WriteUInt16BigEndian(bytes[TransportOffset..], (ushort)sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes[(TransportOffset + 2)..], (ushort)destinationPort);
    }

    public static byte[] UdpReply(FlowKey flow, ReadOnlySpan<byte> payload)
    {
        var ipv4 = flow.LocalAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var header = ipv4 ? 20 : 40;
        if (payload.Length > MaxUdpPayload(ipv4)) throw new ArgumentOutOfRangeException(nameof(payload));
        var bytes = new byte[header + 8 + payload.Length];
        if (ipv4)
        {
            bytes[0] = 0x45; bytes[8] = 64; bytes[9] = 17;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)bytes.Length);
            flow.RemoteAddress.GetAddressBytes().CopyTo(bytes, 12); flow.LocalAddress.GetAddressBytes().CopyTo(bytes, 16);
        }
        else
        {
            bytes[0] = 0x60; bytes[6] = 17; bytes[7] = 64;
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), (ushort)(8 + payload.Length));
            flow.RemoteAddress.GetAddressBytes().CopyTo(bytes, 8); flow.LocalAddress.GetAddressBytes().CopyTo(bytes, 24);
        }
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(header), (ushort)flow.RemotePort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(header + 2), (ushort)flow.LocalPort);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(header + 4), (ushort)(8 + payload.Length));
        payload.CopyTo(bytes.AsSpan(header + 8));
        return bytes;
    }
}
