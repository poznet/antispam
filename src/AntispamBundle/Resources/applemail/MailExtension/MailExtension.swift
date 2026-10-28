import MailKit

/// Principal class of the Mail extension (NSExtensionPrincipalClass).
/// Only the message action capability is used: Mail calls it for every
/// downloaded message, the handler asks antispam and returns an action.
final class MailExtension: NSObject, MEExtension {
    func handlerForMessageActions() -> MEMessageActionHandler {
        MessageActionHandler.shared
    }
}
