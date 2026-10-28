import Foundation

/// Server URL baked in by the antispam download (`GET /plugin/apple-mail/source.zip`
/// replaces the placeholder). A build from the repository (one signed app for
/// every instance, docs/plugin-distribution.md) keeps the placeholder: the
/// user enters the address in the app window on first run.
enum ServerConfig {
    static let bundledServer = "__ANTISPAM_SERVER__"

    static var defaultServer: String {
        bundledServer.hasPrefix("__") ? "" : bundledServer
    }

    /// Base URL of the server from what the user typed or pasted: a bare host
    /// (https:// is added), the setup link `https://host/plugin/setup`, a
    /// download or panel link. Same rules as the Thunderbird plugin
    /// (`normalizeServer` in common.js). Returns "" when unusable.
    static func normalize(_ input: String) -> String {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty { return "" }
        if value.range(of: "^[a-zA-Z][a-zA-Z0-9+.-]*://", options: .regularExpression) == nil {
            value = "https://" + value
        }
        guard var comps = URLComponents(string: value),
              let scheme = comps.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = comps.host, !host.isEmpty,
              comps.user == nil, comps.password == nil else {
            return ""
        }
        var path = comps.path
        if let r = path.range(of: "/(plugin|api/plugin|panel|config|login|q)(/.*)?$", options: [.regularExpression, .caseInsensitive]) {
            path.removeSubrange(r)
        }
        while path.hasSuffix("/") { path.removeLast() }
        comps.path = path
        comps.query = nil
        comps.fragment = nil
        comps.scheme = scheme
        return comps.string ?? ""
    }
}
