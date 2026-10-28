import SwiftUI
import UniformTypeIdentifiers

/// Login, options and manual reports. Apple Mail has no API for custom
/// buttons on a displayed message, so reports are made by dragging messages
/// from Mail onto this window (or picking saved .eml files).
struct ContentView: View {
    private let settings = AntispamSettings.shared
    private var client: AntispamClient { AntispamClient(settings: settings) }

    @State private var server = AntispamSettings.shared.server
    @State private var serverStatus = "Sprawdzanie połączenia…"
    @State private var loggedInEmail = AntispamSettings.shared.email
    @State private var email = ""
    @State private var password = ""
    @State private var autoCheck = AntispamSettings.shared.autoCheck
    @State private var spamAction = AntispamSettings.shared.spamAction
    @State private var quarantineAction = AntispamSettings.shared.quarantineAction
    @State private var verdict = "spam"
    @State private var message = ""
    @State private var busy = false
    @State private var dropTargeted = false
    @State private var pickingFiles = false

    var body: some View {
        Form {
            Section("Serwer antyspamu") {
                HStack {
                    TextField("https://antispam.example.pl", text: $server)
                        .onSubmit(saveServer)
                    Button("Zapisz", action: saveServer)
                }
                Text(serverStatus).font(.caption).foregroundStyle(.secondary)
            }

            if loggedInEmail.isEmpty {
                Section("Logowanie (opcjonalne)") {
                    Text("Bez logowania możesz zgłaszać spam do wspólnej bazy. Zalogowanie adresem skrzynki i hasłem wtyczki (lub IMAP) włącza sprawdzanie nowej poczty, „To nie spam” i reguły dla Twojej skrzynki.")
                        .font(.caption).foregroundStyle(.secondary)
                    TextField("Adres skrzynki", text: $email)
                    SecureField("Hasło wtyczki lub IMAP", text: $password)
                    Button("Zaloguj", action: login).disabled(busy || email.isEmpty || password.isEmpty)
                }
            } else {
                Section("Zalogowano: \(loggedInEmail)") {
                    Toggle("Sprawdzaj nową pocztę przy odbiorze", isOn: $autoCheck)
                        .onChange(of: autoCheck) { settings.autoCheck = $0 }
                    Picker("Spam", selection: $spamAction) {
                        Text("Przenieś do Wiadomości-śmieci").tag(AntispamSettings.SpamAction.move)
                        Text("Oznacz czerwoną flagą").tag(AntispamSettings.SpamAction.flag)
                        Text("Nic nie rób").tag(AntispamSettings.SpamAction.none)
                    }
                    .onChange(of: spamAction) { settings.spamAction = $0 }
                    Picker("Kwarantanna", selection: $quarantineAction) {
                        Text("Pomarańczowe tło").tag(AntispamSettings.QuarantineAction.color)
                        Text("Nic nie rób").tag(AntispamSettings.QuarantineAction.none)
                    }
                    .onChange(of: quarantineAction) { settings.quarantineAction = $0 }
                    Text("Sprawdzanie działa po włączeniu rozszerzenia w Mail → Ustawienia → Rozszerzenia.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Wyloguj") {
                        settings.logout()
                        loggedInEmail = ""
                    }
                }
            }

            Section("Zgłoś wiadomość") {
                Picker("Zgłoszenie", selection: $verdict) {
                    Text("Spam").tag("spam")
                    Text("To nie spam").tag("ham")
                }
                .pickerStyle(.segmented)
                .disabled(loggedInEmail.isEmpty)

                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [6]))
                    .foregroundStyle(dropTargeted ? Color.accentColor : Color.secondary)
                    .frame(height: 110)
                    .overlay(Text("Przeciągnij tutaj wiadomości z Mail\nlub pliki .eml").multilineTextAlignment(.center))
                    .onDrop(of: [.fileURL, .emailMessage], isTargeted: $dropTargeted, perform: handleDrop)

                Button("Wybierz pliki .eml…") { pickingFiles = true }
                    .fileImporter(isPresented: $pickingFiles, allowedContentTypes: [.emailMessage, .data], allowsMultipleSelection: true) { result in
                        if case .success(let urls) = result { reportFiles(urls) }
                    }

                if !message.isEmpty {
                    Text(message).font(.callout)
                }
            }
        }
        .formStyle(.grouped)
        .task { await refreshStatus() }
    }

    // MARK: - actions

    private func saveServer() {
        settings.server = server
        server = settings.server
        Task { await refreshStatus() }
    }

    @MainActor
    private func refreshStatus() async {
        guard !settings.server.isEmpty else {
            serverStatus = "Podaj adres serwera antyspamu."
            return
        }
        do {
            let st = try await client.status()
            serverStatus = st.enabled ? "Połączono z \(settings.server)" : "Wtyczki wyłączone na serwerze"
            if !st.authenticated && !settings.token.isEmpty { settings.logout() }
            loggedInEmail = settings.email
        } catch {
            serverStatus = "Brak połączenia z serwerem: \(error.localizedDescription)"
        }
    }

    private func login() {
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do {
                let res = try await client.login(email: email, password: password)
                loggedInEmail = res.email
                password = ""
                message = "Zalogowano jako \(res.email)."
            } catch {
                message = "Logowanie nieudane: \(error.localizedDescription)"
            }
        }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        for provider in providers {
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url = url { reportFiles([url]) }
                }
            } else if provider.hasItemConformingToTypeIdentifier(UTType.emailMessage.identifier) {
                provider.loadDataRepresentation(forTypeIdentifier: UTType.emailMessage.identifier) { data, _ in
                    if let data = data { report(data, name: provider.suggestedName ?? "wiadomość") }
                }
            }
        }
        return !providers.isEmpty
    }

    private func reportFiles(_ urls: [URL]) {
        for url in urls {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url) else {
                DispatchQueue.main.async { message = "Nie można odczytać pliku \(url.lastPathComponent)." }
                continue
            }
            report(data, name: url.lastPathComponent)
        }
    }

    private func report(_ raw: Data, name: String) {
        let chosen = loggedInEmail.isEmpty ? "spam" : verdict
        Task { @MainActor in
            do {
                let res = try await client.report(raw: raw, verdict: chosen)
                let who = res.sender ?? name
                let learned = !(res.rules ?? []).isEmpty
                message = chosen == "spam"
                    ? "Zgłoszono spam: \(who)" + (learned ? " (nadawca zablokowany)" : "")
                    : "Oznaczono jako nie-spam: \(who)" + (learned ? " (nadawca na białej liście)" : "")
            } catch {
                message = "Nie udało się wysłać zgłoszenia: \(error.localizedDescription)"
            }
        }
    }
}
