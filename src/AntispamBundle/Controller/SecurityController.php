<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Attribute\Route;

class SecurityController extends AbstractController
{
    /**
     * POST is handled by the form_login firewall (check_path). GET - the entry
     * point for anonymous visitors and the redirect after a failed login - sends
     * the user to the login form on the home page; the authentication error
     * stays in the session and is shown there.
     */
    #[Route('/login', name: 'login')]
    public function loginAction(): RedirectResponse
    {
        return $this->redirect($this->generateUrl('antispam_home') . '#logowanie');
    }

    #[Route('/logout', name: 'logout')]
    public function logoutAction()
    {
        // Handled by the security firewall; this method is never executed.
        throw new \LogicException('This method should not be reached - check firewall logout configuration.');
    }
}
