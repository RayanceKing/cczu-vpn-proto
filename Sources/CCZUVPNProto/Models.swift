import Foundation

public struct ProxyServer: Codable, Equatable, Sendable {
    public let address: String
    public let mask: String
    public let gateway: String
    public var dns: String
    public let wins: String

    public init(address: String, mask: String, gateway: String, dns: String, wins: String) {
        self.address = address
        self.mask = mask
        self.gateway = gateway
        self.dns = dns
        self.wins = wins
    }
}

public struct CCZUVPNConfiguration: Sendable {
    public var ssoLoginURL: URL
    public var vpnRootURL: URL
    public var proxyHost: String
    public var proxyPort: UInt16
    public var userAgent: String
    public var skipTLSVerification: Bool

    public init(
        ssoLoginURL: URL = URL(string: "http://sso.cczu.edu.cn/sso/login")!,
        vpnRootURL: URL = URL(string: "https://zmvpn.cczu.edu.cn")!,
        proxyHost: String = "zmvpn.cczu.edu.cn",
        proxyPort: UInt16 = 443,
        userAgent: String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
        skipTLSVerification: Bool = true
    ) {
        self.ssoLoginURL = ssoLoginURL
        self.vpnRootURL = vpnRootURL
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.userAgent = userAgent
        self.skipTLSVerification = skipTLSVerification
    }
}
