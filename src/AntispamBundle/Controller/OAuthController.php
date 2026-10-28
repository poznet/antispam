<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\OAuth\OAuthClient;
use AntispamBundle\Services\OAuth\OAuthException;
use AntispamBundle\Services\OAuth\OAuthSettings;
use AntispamBundle\Services\OAuth\OAuthTokenManager;
use AntispamBundle\Services\PluginService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * OAuth2 for IMAP accounts (Microsoft 365, Google): app settings, consent
 * ("Połącz"), callback and "Rozłącz". See docs/oauth.md.
 *
 * Connect is a GET link (CSRF token in the query): the CSP form-action 'self'
 * would block a form post that redirects to login.microsoftonline.com /
 * accounts.google.com. The pending authorization (state, PKCE verifier,
 * account, provider) lives in the session; the callback accepts each state
 * once, within 15 minutes, for the session that started it.
 */
#[IsGranted('ROLE_ADMIN')]
class OAuthController extends AbstractController
{
    use AuditTrait;

    public const SESSION_KEY = 'antispam_oauth_pending';
    public const STATE_TTL = 900;
    public const MAX_PENDING = 5;

    public function __construct(
        private EntityManagerInterface $em,
        private OAuthSettings $settings,
        private OAuthClient $client,
        private OAuthTokenManager $tokens,
        private PluginService $plugin,
    ) {
    }

    /**
     * Redirect URI registered at the provider: `<public URL>/account/oauth/callback`.
     * The public URL is plugin.public_url (Ustawienia → Wtyczki pocztowe), else the
     * request's scheme + host (needs SYMFONY_TRUSTED_PROXIES behind a TLS proxy).
     */
    public function redirectUri(Request $request): string
    {
        $base = $this->plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath();
        return rtrim($base, '/') . $this->generateUrl('antispam_oauth_callback', [], UrlGeneratorInterface::ABSOLUTE_PATH);
    }

    #[Route('/config/oauth/', name: 'antispam_oauth_config')]
    #[Template('@Antispam/Configuration/oauthConfig.html.twig')]
    public function settingsAction(Request $request)
    {
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('oauth_config', (string)$request->request->get('_token'))) {
                $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
                return $this->redirectToRoute('antispam_oauth_config');
            }
            $post = $request->request->all('oauth');
            if ($errors = OAuthSettings::validate($post)) {
                $this->addFlash('danger', implode(' ', $errors));
                return $this->redirectToRoute('antispam_oauth_config');
            }
            $this->settings->save($post);
            $secrets = [];
            foreach (['microsoft', 'google'] as $p) {
                if (!empty($post[$p . '_client_secret_clear']) || trim((string)($post[$p . '_client_secret'] ?? '')) !== '') {
                    $secrets[] = $p . '_client_secret';
                }
            }
            $this->audit('settings.save', targetType: 'settings', targetId: 'oauth', label: 'Logowanie OAuth', details: AuditLogger::formFields($post, ['microsoft_client_secret', 'google_client_secret']) + ['secrets_changed' => $secrets]);
            $this->addFlash('success', 'Ustawienia logowania OAuth zapisane');
            return $this->redirectToRoute('antispam_oauth_config');
        }

        $accounts = [];
        foreach ($this->em->getRepository(Account::class)->findAll() as $a) {
            if ($a->isOAuth()) {
                $accounts[] = $a;
            }
        }

        return [
            'redirect_uri' => $this->redirectUri($request),
            'redirect_https' => str_starts_with($this->redirectUri($request), 'https://') || preg_match('#^http://(localhost|127\.0\.0\.1)[:/]#', $this->redirectUri($request)),
            'public_url' => $this->plugin->getPublicUrl(),
            'ms_client_id' => $this->settings->clientId(OAuthSettings::MICROSOFT),
            'ms_secret_set' => $this->settings->hasClientSecret(OAuthSettings::MICROSOFT),
            'ms_tenant' => (string)$this->settingsTenantRaw(),
            'google_client_id' => $this->settings->clientId(OAuthSettings::GOOGLE),
            'google_secret_set' => $this->settings->hasClientSecret(OAuthSettings::GOOGLE),
            'accounts' => $accounts,
        ];
    }

    /** "Połącz z Microsoft 365 / Google": GET with the per-account CSRF token. */
    #[Route('/account/oauth/connect/{id}', name: 'antispam_oauth_connect', methods: ['GET'], requirements: ['id' => '\d+'])]
    public function connectAction(int $id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, (string)$request->query->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account || !$account->isOAuth()) {
            $this->addFlash('danger', 'Konto nie istnieje albo nie używa logowania OAuth (zapisz najpierw sposób logowania).');
            return $this->redirectToRoute('antispam_account_index');
        }
        if ($account->isOAuthAppOnly()) {
            $this->addFlash('info', 'Logowanie aplikacji (client credentials) nie wymaga zgody użytkownika - użyj „Test połączenia”.');
            return $this->redirectToRoute('antispam_account_edit', ['id' => $id]);
        }

        $provider = (string)$account->getOAuthProvider();
        $state = OAuthClient::randomState();
        $pkce = OAuthClient::pkce();
        $redirectUri = $this->redirectUri($request);
        try {
            $url = $this->client->authorizationUrl($provider, $redirectUri, $state, $pkce['challenge'], $account->getImapLogin() ?: $account->getEmail(), $account->getOAuthTenant());
        } catch (OAuthException $e) {
            $this->addFlash('danger', $e->getMessage());
            return $this->redirectToRoute('antispam_account_edit', ['id' => $id]);
        }

        $session = $request->getSession();
        $pending = self::livePending((array)$session->get(self::SESSION_KEY, []));
        $pending[$state] = [
            'account_id' => $id,
            'provider' => $provider,
            'method' => $account->getImapAuthMethod(),
            'verifier' => $pkce['verifier'],
            'redirect_uri' => $redirectUri,
            'tenant' => $account->getOAuthTenant(),
            'created' => time(),
        ];
        $session->set(self::SESSION_KEY, array_slice($pending, -self::MAX_PENDING, null, true));

        return new RedirectResponse($url);
    }

    /** Redirect target registered at Microsoft / Google. */
    #[Route('/account/oauth/callback', name: 'antispam_oauth_callback', methods: ['GET'])]
    public function callbackAction(Request $request)
    {
        $session = $request->getSession();
        $pending = self::livePending((array)$session->get(self::SESSION_KEY, []));
        $state = (string)$request->query->get('state', '');
        $entry = $state !== '' ? self::findPending($pending, $state) : null;
        if ($entry !== null) {
            unset($pending[$entry[0]]); // single use, also after an error
        }
        $session->set(self::SESSION_KEY, $pending);

        if ($entry === null) {
            $this->addFlash('danger', 'Logowanie OAuth przerwane: nieprawidłowy lub wygasły parametr state. Zacznij od przycisku „Połącz” na stronie konta (w tej samej przeglądarce, w ciągu 15 minut).');
            return $this->redirectToRoute('antispam_account_index');
        }
        $data = $entry[1];
        $account = $this->em->getRepository(Account::class)->find((int)$data['account_id']);
        if (!$account) {
            $this->addFlash('danger', 'Konto zostało usunięte w trakcie logowania OAuth.');
            return $this->redirectToRoute('antispam_account_index');
        }
        $back = $this->redirectToRoute('antispam_account_edit', ['id' => $account->getId(), '_fragment' => 'oauth']);

        if ($request->query->has('error')) {
            $error = mb_substr((string)$request->query->get('error'), 0, 100);
            $description = mb_substr(trim(strtok((string)$request->query->get('error_description', ''), "\r\n") ?: ''), 0, 300);
            $this->addFlash('danger', 'Dostawca odmówił dostępu: ' . $error . ($description !== '' ? ' - ' . $description : '')
                . ($error === 'access_denied' ? ' (zgoda nie została udzielona; w Microsoft 365 może być potrzebna zgoda administratora).' : ''));
            return $back;
        }
        if ($account->getImapAuthMethod() !== $data['method']) {
            $this->addFlash('danger', 'Sposób logowania konta zmienił się w trakcie logowania OAuth - połącz ponownie.');
            return $back;
        }
        $code = (string)$request->query->get('code', '');
        if ($code === '' || strlen($code) > 4096) {
            $this->addFlash('danger', 'Logowanie OAuth: brak kodu autoryzacji w odpowiedzi dostawcy.');
            return $back;
        }

        try {
            $tokens = $this->client->exchangeCode($data['provider'], $code, $data['verifier'], $data['redirect_uri'], $data['tenant'] ?? null);
        } catch (OAuthException $e) {
            $this->addFlash('danger', 'Nie udało się pobrać tokenu: ' . $e->getMessage());
            return $back;
        }
        $address = OAuthClient::addressFromIdToken($tokens['id_token'] ?? null);
        $login = trim((string)$account->getImapLogin());
        // Gmail only accepts the token owner as the XOAUTH2 user.
        if ($data['provider'] === OAuthSettings::GOOGLE && $address !== null && $login !== '' && strcasecmp($login, $address) !== 0) {
            $this->addFlash('danger', sprintf('Zalogowano jako %s, a login konta to %s. Gmail wymaga, by to był ten sam adres - zaloguj się właściwym kontem Google albo popraw login.', $address, $login));
            return $back;
        }

        $this->tokens->storeConsent($account, $tokens, $address);
        $this->em->flush();
        $this->audit('account.oauth_connected', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: [
            'provider' => $data['provider'],
            'oauth_username' => $address,
        ]);

        $message = 'Połączono z ' . OAuthSettings::LABELS[$data['provider']] . ($address ? ' jako ' . $address : '') . '.';
        if ($address !== null && strcasecmp($account->getOAuthImapUser(), $address) !== 0) {
            $message .= ' Uwaga: logowanie IMAP użyje adresu ' . $account->getOAuthImapUser() . ' (skrzynka współdzielona?) - zalogowany użytkownik musi mieć do niej pełny dostęp.';
        }
        $this->addFlash('success', $message . ' Sprawdź połączenie przyciskiem „Test” na liście kont.');
        return $back;
    }

    #[Route('/account/oauth/disconnect/{id}', name: 'antispam_oauth_disconnect', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function disconnectAction(int $id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account) {
            return $this->redirectToRoute('antispam_account_index');
        }
        $provider = $account->getOAuthProvider();
        $username = $account->getOAuthUsername();
        $account->clearOAuthTokens();
        $this->em->flush();
        $this->audit('account.oauth_disconnected', targetType: 'account', targetId: $id, label: $account->getName(), mailbox: $account->getEmail(), details: [
            'provider' => $provider,
            'oauth_username' => $username,
        ]);
        $this->addFlash('success', 'Tokeny OAuth zostały usunięte z tego serwera. Aby całkiem odebrać dostęp, cofnij go też u dostawcy (myaccount.google.com/permissions albo myapps.microsoft.com).');
        return $this->redirectToRoute('antispam_account_edit', ['id' => $id]);
    }

    private function settingsTenantRaw(): string
    {
        $tenant = $this->settings->microsoftTenant();
        return $tenant === OAuthSettings::DEFAULT_MS_TENANT ? '' : $tenant;
    }

    /** Drops expired entries. */
    public static function livePending(array $pending): array
    {
        return array_filter($pending, static fn ($e) => is_array($e) && (int)($e['created'] ?? 0) > time() - self::STATE_TTL);
    }

    /** @return array{0:string, 1:array}|null constant-time state lookup */
    private static function findPending(array $pending, string $state): ?array
    {
        $found = null;
        foreach ($pending as $key => $entry) {
            if (hash_equals((string)$key, $state)) {
                $found = [(string)$key, $entry];
            }
        }
        return $found;
    }
}
