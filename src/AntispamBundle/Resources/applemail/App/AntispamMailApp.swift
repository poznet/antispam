import SwiftUI

/// Container app of the Mail extension. Mail extensions are only installed as
/// part of an app; this one also handles login, options and spam reports
/// (messages dragged from Mail or opened as .eml files).
@main
struct AntispamMailApp: App {
    var body: some Scene {
        WindowGroup("Antispam Pancernapanda") {
            ContentView()
                .frame(minWidth: 460, minHeight: 560)
        }
    }
}
