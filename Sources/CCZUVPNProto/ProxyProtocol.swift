import Foundation

protocol Packet {
    func build() -> Data
}

struct AuthorizationPacket: Packet {
    let token: String
    let user: String

    func build() -> Data {
        let tokenBytes = Array(token.utf8)
        let userBytes = Array(user.utf8)

        var packet = Data()
        packet.append(0x01) // Version
        packet.append(0x01) // Protocol

        let length = UInt16(19 + userBytes.count + tokenBytes.count)
        packet.append(contentsOf: length.bigEndianBytes)

        packet.append(contentsOf: [
            0, 0, 0, 0,
            1, 0, 0, 0,
            1, 0
        ])

        packet.append(UInt8(userBytes.count))
        packet.append(contentsOf: userBytes)

        packet.append(contentsOf: [2, 0])
        packet.append(UInt8(tokenBytes.count))
        packet.append(contentsOf: tokenBytes)

        packet.append(0xFF)
        return packet
    }
}

struct TCPPacket: Packet {
    let payload: Data

    func build() -> Data {
        var packet = Data([1, 4])
        let length = UInt16(payload.count + 12)
        packet.append(contentsOf: length.bigEndianBytes)
        packet.append(contentsOf: [0, 0, 0, 0])
        packet.append(contentsOf: Int32(1).bigEndianBytes)
        packet.append(payload)
        return packet
    }
}

let heartbeatPacket = Data([1, 1, 0, 12, 0, 0, 0, 0, 3, 0, 0, 0])

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian, Array.init)
    }
}
