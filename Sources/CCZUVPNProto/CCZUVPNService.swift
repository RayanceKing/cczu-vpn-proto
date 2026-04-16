import Foundation

public actor CCZUVPNService {
    private let configuration: CCZUVPNConfiguration
    private let authClient: SSOAuthClient

    private var connection: TLSProxyConnection?
    private var pollingTask: Task<Void, Never>?
    private var pollingStopSignal = false
    private var heartbeatThrottle = false

    public private(set) var proxyServer: ProxyServer?

    public init(configuration: CCZUVPNConfiguration = .init()) {
        self.configuration = configuration
        self.authClient = SSOAuthClient(configuration: configuration)
    }

    public func webVPNAvailable() async -> Bool {
        await authClient.webVPNAvailable()
    }

    @discardableResult
    public func startService(user: String, password: String) async -> Bool {
        do {
            try await start(user: user, password: password)
            return true
        } catch {
            return false
        }
    }

    public func start(user: String, password: String) async throws {
        guard connection == nil else {
            throw CCZUVPNError.malformedServerData("Service is already running")
        }

        let auth = try await authClient.authorize(user: user, password: password)
        let conn = TLSProxyConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            skipTLSVerification: configuration.skipTLSVerification
        )

        try await conn.connect()
        try await conn.write(AuthorizationPacket(token: auth.token, user: auth.user).build())

        var server = try await consumeAuthorization(on: conn)
        server.dns = auth.dns

        proxyServer = server
        connection = conn
    }

    public func serviceAvailable() -> Bool {
        connection != nil
    }

    @discardableResult
    public func stopService() async -> Bool {
        guard let connection else {
            return false
        }

        stopPollingPacket()
        await connection.disconnect()
        self.connection = nil
        self.proxyServer = nil
        return true
    }

    public func sendPacket(_ packet: Data) async -> Bool {
        guard let connection else {
            return false
        }

        do {
            try await connection.write(packet)
            return true
        } catch {
            return false
        }
    }

    public func sendTCPPacket(_ payload: Data) async -> Bool {
        await sendPacket(TCPPacket(payload: payload).build())
    }

    public func sendHeartbeat() async -> Bool {
        await sendPacket(heartbeatPacket)
    }

    public func receivePacket(size: Int) async -> Data {
        guard let connection else {
            return Data([0, 0, 0, 0])
        }

        do {
            let body = try await connection.readExact(size)
            var frame = Data()
            frame.append(contentsOf: UInt32(body.count).bigEndianBytes)
            frame.append(body)
            return frame
        } catch {
            return Data([0, 0, 0, 0])
        }
    }

    public func startPollingPacket(_ callback: @escaping @Sendable (_ size: UInt32, _ packet: Data) -> Void) {
        stopPollingPacket()
        pollingStopSignal = false

        pollingTask = Task {
            while !pollingStopSignal {
                do {
                    if let packet = try await tryReadPacketData() {
                        if packet.count != 4 && packet.first != 3 {
                            callback(UInt32(packet.count), packet)
                        } else {
                            await sendHeartbeatThrottled()
                        }
                    } else {
                        await sendHeartbeatThrottled()
                    }
                } catch {
                    callback(0, Data(String(describing: error).utf8))
                    break
                }
            }

            pollingStopSignal = false
        }
    }

    public func stopPollingPacket() {
        pollingStopSignal = true
        pollingTask?.cancel()
        pollingTask = nil
    }

    private func sendHeartbeatThrottled() async {
        guard !heartbeatThrottle else {
            return
        }

        heartbeatThrottle = true
        Task {
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            _ = await self.sendHeartbeat()
            self.setHeartbeatThrottle(false)
        }
    }

    private func setHeartbeatThrottle(_ value: Bool) {
        heartbeatThrottle = value
    }

    private func tryReadPacketData() async throws -> Data? {
        guard let connection else {
            throw CCZUVPNError.transportDisconnected
        }

        let header: Data
        do {
            header = try await connection.readExact(8, timeoutSeconds: 0.5)
        } catch CCZUVPNError.timeout {
            return nil
        }

        guard header.count == 8 else {
            return nil
        }

        let bytes = [UInt8](header)
        let isHeartbeatLike = bytes[0] == 1 && bytes[1] == 2 && bytes[2] == 0 && (bytes[3] == 10 || bytes[3] == 12)

        if isHeartbeatLike {
            _ = try? await connection.readAny(max: 2048, timeoutSeconds: 5)
            return nil
        }

        let packetLength = Int(UInt16(bytes[3]) << 8 | UInt16(bytes[2])) - 8
        if packetLength <= 0 {
            return nil
        }

        return try await connection.readExact(packetLength, timeoutSeconds: 5)
    }

    private func consumeAuthorization(on connection: TLSProxyConnection) async throws -> ProxyServer {
        _ = try await connection.readExact(10)

        let status = try await connection.readExact(2)
        if status != Data([0, 0]) {
            throw CCZUVPNError.authorizationFailed
        }

        let ipHeader = [UInt8](try await connection.readExact(3))
        guard ipHeader == [11, 0, 4] else {
            throw CCZUVPNError.malformedServerData("Unexpected virtual address header: \(ipHeader)")
        }
        let virtualAddress = try await connection.readExact(4)

        let maskHeader = [UInt8](try await connection.readExact(3))
        guard maskHeader == [12, 0, 4] else {
            throw CCZUVPNError.malformedServerData("Unexpected mask header: \(maskHeader)")
        }
        let rawMask = [UInt8](try await connection.readExact(4))

        var gateway = Data([0, 0, 0, 0])
        var dns = ""
        var wins = ""

        while true {
            let status = [UInt8](try await connection.readExact(2))
            if status[0] == 43 {
                break
            }

            let length = Int((try await connection.readExact(1)).first ?? 0)
            let payload = try await connection.readExact(length)

            switch status {
            case [35, 0]:
                gateway = payload
            case [36, 0]:
                dns = String(decoding: payload, as: UTF8.self)
            case [37, 0]:
                wins = String(decoding: payload, as: UTF8.self)
            default:
                throw CCZUVPNError.malformedServerData("Unexpected status pair: \(status)")
            }
        }

        while true {
            let byte = try await connection.readExact(1).first ?? 0
            if byte == 255 {
                break
            }
        }

        let mask = Self.prefixMaskToDotted(rawMask)

        return ProxyServer(
            address: Self.ipString(from: virtualAddress),
            mask: mask,
            gateway: Self.ipString(from: gateway),
            dns: dns,
            wins: wins
        )
    }

    private static func ipString(from data: Data) -> String {
        data.map { String($0) }.joined(separator: ".")
    }

    private static func prefixMaskToDotted(_ rawMask: [UInt8]) -> String {
        let ones = rawMask.reduce(0) { partial, value in
            partial + value.nonzeroBitCount
        }

        var bits = Array(repeating: true, count: ones)
        bits.append(contentsOf: Array(repeating: false, count: max(0, 32 - ones)))

        var octets: [UInt8] = []
        for chunk in stride(from: 0, to: 32, by: 8) {
            let slice = bits[chunk..<(chunk + 8)]
            let byte = slice.reduce(UInt8(0)) { partial, bit in
                (partial << 1) | (bit ? 1 : 0)
            }
            octets.append(byte)
        }

        return octets.map(String.init).joined(separator: ".")
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian, Array.init)
    }
}
