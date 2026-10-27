<?php

namespace AntispamBundle\Controller;

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
    public function indexAction(AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('@Antispam/Home/index.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error' => $authenticationUtils->getLastAuthenticationError(),
        ]);
    }
}
