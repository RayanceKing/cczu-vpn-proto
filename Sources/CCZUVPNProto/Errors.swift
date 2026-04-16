import Foundation

public enum CCZUVPNError: Error, LocalizedError, Sendable {
    case invalidResponse
    case missingLocation
    case missingClientInfo
    case webVPNUnavailable
    case authorizationFailed
    case malformedServerData(String)
    case transportDisconnected
    case timeout
    case unsupportedStatus(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Invalid HTTP response."
        case .missingLocation:
            return "Redirect response is missing Location header."
        case .missingClientInfo:
            return "Missing clientInfo cookie from SSO login response."
        case .webVPNUnavailable:
            return "WebVPN is unavailable for this account."
        case .authorizationFailed:
            return "Proxy authorization failed."
        case let .malformedServerData(message):
            return "Malformed proxy server data: \(message)"
        case .transportDisconnected:
            return "TLS transport disconnected."
        case .timeout:
            return "Operation timed out."
        case let .unsupportedStatus(code):
            return "Unexpected HTTP status: \(code)."
        }
    }
}
