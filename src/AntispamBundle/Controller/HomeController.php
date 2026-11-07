<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Security\YubiKey\YubiKeyService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * Public home page (product landing) with the admin login form embedded in
 * the "Panel" section (#logowanie). The form posts to /login (form_login
 * check_path); the admin dashboard lives at /panel.
 */
class HomeController extends AbstractController
{
    #[Route('/', name: 'antispam_home', methods: ['GET'])]
    public function indexAction(AuthenticationUtils $authenticationUtils, ?YubiKeyService $yubiKeys = null): Response
    {
        $error = $authenticationUtils->getLastAuthenticationError();
        return $this->render('@Antispam/Home/index.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error' => $error,
            // Passwordless "Zaloguj kluczem YubiKey" (YubiKeyAuthenticator).
            'yubikey_login' => $yubiKeys?->isPasswordlessEnabled() ?? false,
            // Re-open the key form after a failed key login (its messages mention the key).
            'yubikey_open' => $error !== null && str_contains($error->getMessageKey(), 'YubiKey'),
        ]);
    }
}
