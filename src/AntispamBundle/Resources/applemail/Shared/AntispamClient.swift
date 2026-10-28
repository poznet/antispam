import Foundation

/// Client for the antispam plugin API (`/api/plugin/*`, see docs/thunderbird.md).
final class AntispamClient {
    /// Only the head of a message is needed for scoring (headers + text body).
    static let maxUploadBytes = 1024 * 1024

    struct APIError: LocalizedError {
        let status: Int
        let message: String
        var errorDescription: String? { message }
    }

    struct Status: Decodable {
        let enabled: Bool
        let version: String?
        let anonymous_reports: Bool
        let check_enabled: Bool
        let authenticated: Bool
        let email: String?
    }

    struct Login: Decodable {
        let token: String
        let email: String
        let expires_at: String
    }

    struct Report: Decodable {
        let verdict: String
        let sender: String?
        let rules: [String]?
        let authenticated: Bool?
    }

    struct Reason: Decodable {
        let rule: String
        let score: Int
    }

    struct Check: Decodable {
        let decision: String
        let spam: Bool
        let score: Int
        let spam_threshold: Int
        let quarantine_threshold: Int
        let reasons: [Reason]?
        let sender: String?
        let subject: String?
    }

    private let settings: AntispamSettings
    private let session: URLSession

    init(settings: AntispamSettings = .shared) {
        self.settings = settings
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 20
        session = URLSession(configuration: cfg)
    }

    func status() async throws -> Status {
        try await call("/api/plugin/status", body: nil)
    }

    func login(email: String, password: String) async throws -> Login {
        let res: Login = try await call("/api/plugin/login", body: ["email": email, "password": password], auth: false)
        settings.token = res.token
        settings.email = res.email
        return res
    }

    /// verdict: "spam" (anonymous allowed) or "ham" (login required).
    func report(raw: Data, verdict: String) async throws -> Report {
        try await call("/api/plugin/report", body: ["verdict": verdict, "raw_base64": Self.base64(raw)])
    }

    func check(raw: Data) async throws -> Check {
        try await call("/api/plugin/check", body: ["raw_base64": Self.base64(raw)])
    }

    static func base64(_ raw: Data) -> String {
        raw.prefix(maxUploadBytes).base64EncodedString()
    }

    private func call<T: Decodable>(_ path: String, body: [String: String]?, auth: Bool = true) async throws -> T {
        let server = settings.server
        guard !server.isEmpty, let url = URL(string: server + path) else {
            throw APIError(status: 0, message: "Nie ustawiono adresu serwera antyspamu.")
        }
        var req = URLRequest(url: url)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body = body {
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        if auth && !settings.token.isEmpty {
            req.setValue("Bearer " + settings.token, forHTTPHeaderField: "Authorization")
        }

        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            if status == 401 && auth && !settings.token.isEmpty {
                // Token expired or account removed - fall back to anonymous mode.
                settings.logout()
            }
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw APIError(status: status, message: msg ?? "HTTP \(status)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
