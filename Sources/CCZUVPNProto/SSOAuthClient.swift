import Foundation

private struct ElinkMessage<T: Decodable>: Decodable {
    let code: String
    let messages: String
    let data: T
}

private struct ElinkProxyData: Decodable {
    let token: String
    let server: String
    let gatewayList: [ElinkProxyGateway]

    enum CodingKeys: String, CodingKey {
        case token
        case server
        case gatewayList = "gateway_list"
    }
}

private struct ElinkProxyGateway: Decodable {
    let dns: String
}

private struct ElinkLoginInfo: Decodable {
    let userId: String

    enum CodingKeys: String, CodingKey {
        case userId
    }
}

struct AuthorizationContext: Sendable {
    let token: String
    let user: String
    let dns: String
}

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

actor SSOAuthClient {
    private let configuration: CCZUVPNConfiguration
    private let cookieStorage = HTTPCookieStorage()
    private let redirectDelegate = NoRedirectDelegate()
    private lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieStorage = cookieStorage
        cfg.httpCookieAcceptPolicy = .always
        cfg.httpShouldSetCookies = true
        return URLSession(configuration: cfg, delegate: redirectDelegate, delegateQueue: nil)
    }()

    init(configuration: CCZUVPNConfiguration) {
        self.configuration = configuration
    }

    func webVPNAvailable() async -> Bool {
        do {
            let (_, response) = try await request(
                url: configuration.ssoLoginURL,
                method: "GET"
            )
            return response.statusCode == 302
        } catch {
            return false
        }
    }

    func authorize(user: String, password: String) async throws -> AuthorizationContext {
        let (initialData, initialResponse) = try await request(url: configuration.ssoLoginURL, method: "GET")

        if initialResponse.statusCode == 200 {
            _ = initialData
            throw CCZUVPNError.webVPNUnavailable
        }

        guard initialResponse.statusCode == 302 else {
            throw CCZUVPNError.unsupportedStatus(initialResponse.statusCode)
        }

        guard let location = initialResponse.value(forHTTPHeaderField: "Location"),
              let firstRedirectURL = URL(string: location) else {
            throw CCZUVPNError.missingLocation
        }

        let (loginPageData, loginPageResponse) = try await followRedirects(from: firstRedirectURL)
        let loginPageHTML = String(decoding: loginPageData, as: UTF8.self)
        var hiddenFields = Self.extractHiddenFields(from: loginPageHTML)
        hiddenFields["username"] = user
        hiddenFields["password"] = Data(password.utf8).base64EncodedString()

        let (loginResponseData, loginResponse) = try await request(
            url: loginPageResponse.url ?? firstRedirectURL,
            method: "POST",
            form: hiddenFields
        )

        _ = loginResponseData
        guard let postLoginLocation = loginResponse.value(forHTTPHeaderField: "Location"),
              let postLoginURL = URL(string: postLoginLocation) else {
            throw CCZUVPNError.missingLocation
        }

        let (_, finalResponse) = try await request(url: postLoginURL, method: "GET")
        copyResponseCookies(to: configuration.vpnRootURL, response: finalResponse)

        guard let clientInfo = findCookie(named: "clientInfo"),
              let decoded = Data(base64Encoded: clientInfo.value) else {
            throw CCZUVPNError.missingClientInfo
        }

        let loginInfo = try JSONDecoder().decode(ElinkLoginInfo.self, from: decoded)
        let proxyRule = try await fetchProxyRule(userID: loginInfo.userId)
        guard let dns = proxyRule.gatewayList.first?.dns else {
            throw CCZUVPNError.malformedServerData("Missing gateway DNS")
        }

        return AuthorizationContext(token: proxyRule.token, user: user, dns: dns)
    }

    private func fetchProxyRule(userID: String) async throws -> ElinkProxyData {
        let path = "/enlink/api/client/user/terminal/rules/\(userID)"
        let url = configuration.vpnRootURL.appendingPathComponent(path)
        let (data, response) = try await request(url: url, method: "GET")
        guard response.statusCode == 200 else {
            throw CCZUVPNError.unsupportedStatus(response.statusCode)
        }

        return try JSONDecoder().decode(ElinkMessage<ElinkProxyData>.self, from: data).data
    }

    private func request(
        url: URL,
        method: String,
        form: [String: String]? = nil
    ) async throws -> (Data, HTTPURLResponse) {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(configuration.userAgent, forHTTPHeaderField: "User-Agent")

        if let form {
            req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            let query = form
                .map { key, value in
                    let escapedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
                    let escapedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
                    return "\(escapedKey)=\(escapedValue)"
                }
                .joined(separator: "&")
            req.httpBody = query.data(using: .utf8)
        }

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw CCZUVPNError.invalidResponse
        }

        return (data, http)
    }

    private func followRedirects(from startURL: URL) async throws -> (Data, HTTPURLResponse) {
        var current = startURL

        for _ in 0..<16 {
            let (data, response) = try await request(url: current, method: "GET")
            if response.statusCode == 302 {
                guard let location = response.value(forHTTPHeaderField: "Location"),
                      let next = URL(string: location) else {
                    throw CCZUVPNError.missingLocation
                }
                current = next
                continue
            }
            return (data, response)
        }

        throw CCZUVPNError.malformedServerData("Too many redirects")
    }

    private func copyResponseCookies(to targetURL: URL, response: HTTPURLResponse) {
        guard let setCookie = response.value(forHTTPHeaderField: "Set-Cookie") else {
            return
        }
        let headers = ["Set-Cookie": setCookie]
        let cookies = HTTPCookie.cookies(withResponseHeaderFields: headers, for: response.url ?? targetURL)
        for cookie in cookies {
            var props = cookie.properties ?? [:]
            props[.domain] = targetURL.host
            if let copied = HTTPCookie(properties: props) {
                cookieStorage.setCookie(copied)
            }
        }
    }

    private func findCookie(named name: String) -> HTTPCookie? {
        cookieStorage.cookies?.first(where: { $0.name == name })
    }

    private static func extractHiddenFields(from html: String) -> [String: String] {
        let pattern = #"<input[^>]*type=[\"']hidden[\"'][^>]*>"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return [:]
        }

        let source = html as NSString
        var fields: [String: String] = [:]

        for match in regex.matches(in: html, range: NSRange(location: 0, length: source.length)) {
            let tag = source.substring(with: match.range)
            guard let name = extract(attribute: "name", from: tag),
                  let value = extract(attribute: "value", from: tag) else {
                continue
            }
            fields[name] = value
        }

        return fields
    }

    private static func extract(attribute: String, from inputTag: String) -> String? {
        let pattern = #"\#(attribute)=[\"']([^\"']*)[\"']"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }

        let source = inputTag as NSString
        guard let match = regex.firstMatch(in: inputTag, range: NSRange(location: 0, length: source.length)),
              match.numberOfRanges > 1 else {
            return nil
        }
        return source.substring(with: match.range(at: 1))
    }
}
