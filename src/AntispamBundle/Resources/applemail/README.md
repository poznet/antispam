# Antispam Pancernapanda – rozszerzenie Apple Mail (kod źródłowy)

To jest **kod źródłowy**, nie gotowa aplikacja. Apple Mail od macOS 12 przyjmuje
wyłącznie rozszerzenia MailKit osadzone w podpisanej aplikacji – starych wtyczek
`.mailbundle` nie da się już instalować. Aplikację trzeba zbudować w Xcode
i podpisać własnym kontem Apple Developer.

## Co robi

| Funkcja | Gdzie | Logowanie |
|---|---|---|
| Sprawdzanie nowej poczty przy odbiorze (spam → Wiadomości-śmieci / czerwona flaga, kwarantanna → pomarańczowe tło) | rozszerzenie Mail (`MEMessageActionHandler`) | wymagane |
| Zgłoś spam (do wspólnej bazy; zalogowany: nadawca na czarną listę) | aplikacja – przeciągnij wiadomość z Mail na okno lub wybierz plik `.eml` | opcjonalne |
| To nie spam (nadawca na białą listę) | aplikacja – j.w. | wymagane |

Mail nie udostępnia rozszerzeniom własnych przycisków przy wyświetlanej wiadomości
ani informacji o tym, że użytkownik oznaczył wiadomość jako śmieci – dlatego
zgłoszenia idą przez okno aplikacji.

Sprawdzane są tylko wiadomości zaadresowane do zalogowanej skrzynki (jak we wtyczce
Thunderbird), żeby reguły jednego konta nie działały na inne konta w Mail.

## Wymagania

- macOS 13+ z pełnym **Xcode** (same Command Line Tools nie wystarczą),
- konto **Apple Developer** (99 USD/rok) – do podpisu, App Group i notaryzacji,
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`) albo ręczne utworzenie projektu (niżej).

## Budowanie

```bash
cd applemail
# w project.yml wpisz DEVELOPMENT_TEAM (Team ID z developer.apple.com)
xcodegen generate
open AntispamMail.xcodeproj
```

W Xcode: *Signing & Capabilities* obu targetów – wybierz zespół, sprawdź, że
**App Groups** zawiera `<TeamID>.pl.pancernapanda.antispam` (aplikacja i rozszerzenie
muszą mieć tę samą grupę – tak dzielą się adresem serwera i tokenem logowania).
Potem *Product → Archive*.

Bez XcodeGen: *File → New → Project → macOS App* (SwiftUI), potem
*File → New → Target → Mail Extension* (zaznacz tylko „Message Action”),
podmień wygenerowane pliki na te z `App/`, `MailExtension/`, `Shared/`
(`Shared/` do obu targetów), dodaj App Group i klucz `AntispamAppGroup`
w Info.plist obu targetów (wartość: `$(TeamIdentifierPrefix)pl.pancernapanda.antispam`).
Klucze `NSExtension` z `project.yml` porównaj z szablonem Xcode.

## Dystrybucja

- **Własny Mac / testy:** uruchom z Xcode, potem *Mail → Ustawienia → Rozszerzenia* → włącz „Antispam Pancernapanda”.
- **Dla użytkowników poza App Store:** *Organizer → Distribute App → Developer ID*,
  notaryzacja (`notarytool`), rozpakowany `.app` do `/Applications`. Bez notaryzacji
  Gatekeeper zablokuje aplikację.
- **Mac App Store:** możliwe (rozszerzenia Mail są tam wyświetlane), wymaga przeglądu Apple.

## Adres serwera

Plik pobrany z panelu antyspamu ma adres serwera wpisany w `Shared/ServerConfig.swift`.
W kopii z repozytorium jest placeholder – adres podaje się w oknie aplikacji.

## Konfiguracja w aplikacji

1. Uruchom aplikację, sprawdź adres serwera (status „Połączono z …”).
2. Opcjonalnie zaloguj się adresem skrzynki i **hasłem wtyczki** (ustawianym na koncie
   w panelu antyspamu) albo hasłem IMAP.
3. *Mail → Ustawienia → Rozszerzenia* → zaznacz „Antispam Pancernapanda”.

API serwera: `/api/plugin/*`, opis w `docs/thunderbird.md` i `docs/apple-mail.md` repozytorium antyspamu.
