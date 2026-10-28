import Foundation
import MailKit

/// On-arrival check: every message Mail downloads is sent to antispam
/// (`POST /api/plugin/check`) and the decision is applied locally:
/// spam -> move to Junk (or red flag), quarantine -> orange background (optional).
///
/// Like the Thunderbird plugin, only messages addressed to the logged-in
/// mailbox are checked, so the rules of one account are never applied to
/// another account configured in Mail. Nothing happens when not logged in.
final class MessageActionHandler: NSObject, MEMessageActionHandler {
    static let shared = MessageActionHandler()

    private let settings = AntispamSettings.shared
    private lazy var client = AntispamClient(settings: settings)

    /// Delivery headers used to match BCC / alias deliveries to the mailbox.
    var requiredHeaders: [String] { ["delivered-to", "x-original-to", "envelope-to"] }

    func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
        guard settings.isLoggedIn, settings.autoCheck, message.state == .received,
              isAddressedToMailbox(message) else {
            completionHandler(nil)
            return
        }
        guard let raw = message.rawData else {
            // Headers only so far - ask Mail to call again with the body.
            completionHandler(.invokeAgainWithBody)
            return
        }

        Task {
            do {
                let res = try await client.check(raw: raw)
                completionHandler(decision(for: res.decision))
            } catch {
                // Server unreachable / token expired: leave the message alone.
                NSLog("antispam: check failed: %@", error.localizedDescription)
                completionHandler(nil)
            }
        }
    }

    private func decision(for verdict: String) -> MEMessageActionDecision? {
        switch verdict {
        case "spam":
            switch settings.spamAction {
            case .move: return .action(.moveToJunk)
            case .flag: return .action(.flag(.red))
            case .none: return nil
            }
        case "quarantine":
            return settings.quarantineAction == .color ? .action(.setBackgroundColor(.orange)) : nil
        default:
            return nil
        }
    }

    private func isAddressedToMailbox(_ message: MEMessage) -> Bool {
        let mailbox = settings.email.lowercased()
        guard !mailbox.isEmpty else { return false }
        let recipients = message.allRecipientAddresses.compactMap { $0.addressString?.lowercased() }
        if recipients.contains(mailbox) { return true }
        let headers = message.headers ?? [:]
        for (name, values) in headers where requiredHeaders.contains(name.lowercased()) {
            if values.contains(where: { $0.lowercased().contains(mailbox) }) { return true }
        }
        return false
    }
}
