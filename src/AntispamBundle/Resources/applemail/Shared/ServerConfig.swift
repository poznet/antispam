import Foundation

/// Server URL baked in by the antispam download (`GET /plugin/apple-mail/source.zip`
/// replaces the placeholder). When building from the repository, set it in the
/// app's settings instead.
enum ServerConfig {
    static let bundledServer = "__ANTISPAM_SERVER__"

    static var defaultServer: String {
        bundledServer.hasPrefix("__") ? "" : bundledServer
    }
}
