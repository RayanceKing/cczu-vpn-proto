import Foundation
import Network
import Security

actor TLSProxyConnection {
    private enum ReadRequest {
        case exact(Int, CheckedContinuation<Data, Error>)
        case any(Int, CheckedContinuation<Data?, Error>)
    }

    private let host: String
    private let port: UInt16
    private let skipTLSVerification: Bool
    private let queue = DispatchQueue(label: "cczu.vpn.tls.connection")

    private var connection: NWConnection?
    private var pendingReads: [ReadRequest] = []
    private var buffer = Data()
    private var isClosed = false

    init(host: String, port: UInt16, skipTLSVerification: Bool) {
        self.host = host
        self.port = port
        self.skipTLSVerification = skipTLSVerification
    }

    func connect() async throws {
        let tls = NWProtocolTLS.Options()
        if skipTLSVerification {
            sec_protocol_options_set_verify_block(
                tls.securityProtocolOptions,
                { _, _, completion in completion(true) },
                queue
            )
        }

        let parameters = NWParameters(tls: tls)
        parameters.includePeerToPeer = false

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw CCZUVPNError.transportDisconnected
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        self.connection = connection

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    continuation.resume(returning: ())
                case let .failed(error):
                    continuation.resume(throwing: error)
                case .cancelled:
                    continuation.resume(throwing: CCZUVPNError.transportDisconnected)
                default:
                    break
                }
            }
            connection.start(queue: self.queue)
        }

        receiveNextChunk()
    }

    func disconnect() {
        isClosed = true
        connection?.cancel()
        connection = nil
        let requests = pendingReads
        pendingReads.removeAll()

        for request in requests {
            switch request {
            case let .exact(_, continuation):
                continuation.resume(throwing: CCZUVPNError.transportDisconnected)
            case let .any(_, continuation):
                continuation.resume(throwing: CCZUVPNError.transportDisconnected)
            }
        }
    }

    func write(_ data: Data) async throws {
        guard let connection, !isClosed else {
            throw CCZUVPNError.transportDisconnected
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { maybeError in
                if let maybeError {
                    continuation.resume(throwing: maybeError)
                } else {
                    continuation.resume(returning: ())
                }
            })
        }
    }

    func readExact(_ length: Int, timeoutSeconds: TimeInterval? = nil) async throws -> Data {
        if length <= 0 {
            return Data()
        }

        if buffer.count >= length {
            return take(length)
        }

        let readTask = Task { () throws -> Data in
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                pendingReads.append(.exact(length, continuation))
            }
        }

        if let timeoutSeconds {
            let timeoutTask = Task {
                try await Task.sleep(nanoseconds: Self.toNanoseconds(timeoutSeconds))
                throw CCZUVPNError.timeout
            }

            defer {
                readTask.cancel()
                timeoutTask.cancel()
            }

            return try await withThrowingTaskGroup(of: Data.self) { group in
                group.addTask { try await readTask.value }
                group.addTask { _ = try await timeoutTask.value; return Data() }
                let first = try await group.next()!
                group.cancelAll()
                return first
            }
        }

        return try await readTask.value
    }

    func readAny(max length: Int, timeoutSeconds: TimeInterval? = nil) async throws -> Data? {
        if length <= 0 {
            return Data()
        }

        if !buffer.isEmpty {
            return take(min(length, buffer.count))
        }

        let readTask = Task { () throws -> Data? in
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
                pendingReads.append(.any(length, continuation))
            }
        }

        if let timeoutSeconds {
            let timeoutTask = Task {
                try await Task.sleep(nanoseconds: Self.toNanoseconds(timeoutSeconds))
                throw CCZUVPNError.timeout
            }

            defer {
                readTask.cancel()
                timeoutTask.cancel()
            }

            return try await withThrowingTaskGroup(of: Data?.self) { group in
                group.addTask { try await readTask.value }
                group.addTask { _ = try await timeoutTask.value; return nil }
                let first = try await group.next()!
                group.cancelAll()
                return first
            }
        }

        return try await readTask.value
    }

    private func receiveNextChunk() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else {
                return
            }

            Task {
                if let error {
                    await self.failPending(error)
                    return
                }

                if let data, !data.isEmpty {
                    await self.append(data)
                }

                if isComplete {
                    await self.failPending(CCZUVPNError.transportDisconnected)
                    return
                }

                await self.receiveNextChunk()
            }
        }
    }

    private func append(_ data: Data) {
        buffer.append(data)
        satisfyPendingReads()
    }

    private func satisfyPendingReads() {
        while let request = pendingReads.first {
            switch request {
            case let .exact(length, continuation):
                guard buffer.count >= length else {
                    return
                }
                pendingReads.removeFirst()
                continuation.resume(returning: take(length))
            case let .any(max, continuation):
                guard !buffer.isEmpty else {
                    return
                }
                pendingReads.removeFirst()
                continuation.resume(returning: take(min(max, buffer.count)))
            }
        }
    }

    private func take(_ count: Int) -> Data {
        let prefix = buffer.prefix(count)
        buffer.removeFirst(count)
        return Data(prefix)
    }

    private func failPending(_ error: Error) {
        isClosed = true
        let requests = pendingReads
        pendingReads.removeAll()
        for request in requests {
            switch request {
            case let .exact(_, continuation):
                continuation.resume(throwing: error)
            case let .any(_, continuation):
                continuation.resume(throwing: error)
            }
        }
    }

    private static func toNanoseconds(_ seconds: TimeInterval) -> UInt64 {
        if seconds <= 0 {
            return 0
        }
        let ns = seconds * 1_000_000_000
        if ns >= Double(UInt64.max) {
            return UInt64.max
        }
        return UInt64(ns)
    }
}
