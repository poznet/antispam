<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'login')]
    public function loginAction(AuthenticationUtils $authenticationUtils)
    {
        return $this->render('@Antispam/Security/login.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error' => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }

    #[Route('/logout', name: 'logout')]
    public function logoutAction()
    {
        // Handled by the security firewall; this method is never executed.
        throw new \LogicException('This method should not be reached - check firewall logout configuration.');
    }
}
