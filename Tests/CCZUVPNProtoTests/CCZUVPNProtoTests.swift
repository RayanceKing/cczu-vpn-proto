import Foundation
import Testing
@testable import CCZUVPNProto

@Test("TCP packet encoding matches Rust layout")
func tcpPacketEncoding() {
    let payload = Data([0x01, 0x02, 0x03])
    let packet = TCPPacket(payload: payload).build()

    #expect(packet.prefix(2) == Data([1, 4]))
    #expect(packet.count == 15)
    #expect(packet.suffix(3) == payload)
}

@Test("Authorization packet contains user/token and terminator")
func authorizationPacketEncoding() {
    let packet = AuthorizationPacket(token: "token", user: "user").build()

    #expect(packet.first == 0x01)
    #expect(packet.dropFirst(2).contains(0xFF))
    #expect(packet.suffix(1) == Data([0xFF]))
}
