import Foundation

/// Settings shared by the container app (login, options) and the Mail
/// extension (on-arrival checks) through the App Group defaults.
///
/// The App Group identifier comes from the `AntispamAppGroup` Info.plist key
/// (`$(TeamIdentifierPrefix)pl.pancernapanda.antispam`, see project.yml), so it
/// follows the signing team.
final class AntispamSettings {
    static let shared = AntispamSettings()

    enum SpamAction: String, CaseIterable {
        case move   // move to Junk
        case flag   // red flag, stays in Inbox
        case none
    }

    enum QuarantineAction: String, CaseIterable {
        case color  // orange background
        case none
    }

    private let defaults: UserDefaults

    init() {
        let group = Bundle.main.object(forInfoDictionaryKey: "AntispamAppGroup") as? String
        defaults = group.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    var server: String {
        get {
            let s = ServerConfig.normalize(defaults.string(forKey: "server") ?? "")
            return s.isEmpty ? ServerConfig.normalize(ServerConfig.defaultServer) : s
        }
        // Pasted setup links (https://host/plugin/setup) are cut to the base URL.
        set { defaults.set(ServerConfig.normalize(newValue), forKey: "server") }
    }

    var token: String {
        get { defaults.string(forKey: "token") ?? "" }
        set { defaults.set(newValue, forKey: "token") }
    }

    var email: String {
        get { defaults.string(forKey: "email") ?? "" }
        set { defaults.set(newValue, forKey: "email") }
    }

    /// Logged in: check new mail on arrival (Mail extension).
    var autoCheck: Bool {
        get { defaults.object(forKey: "autoCheck") as? Bool ?? true }
        set { defaults.set(newValue, forKey: "autoCheck") }
    }

    var spamAction: SpamAction {
        get { SpamAction(rawValue: defaults.string(forKey: "spamAction") ?? "") ?? .move }
        set { defaults.set(newValue.rawValue, forKey: "spamAction") }
    }

    var quarantineAction: QuarantineAction {
        get { QuarantineAction(rawValue: defaults.string(forKey: "quarantineAction") ?? "") ?? .none }
        set { defaults.set(newValue.rawValue, forKey: "quarantineAction") }
    }

    var isLoggedIn: Bool { !token.isEmpty }

    func logout() {
        token = ""
        email = ""
    }
}
