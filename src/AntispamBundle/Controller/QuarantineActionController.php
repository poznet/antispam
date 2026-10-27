<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\DigestTokenService;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Public endpoints behind the quarantine digest links (no login - the signed
 * token is the credential).
 *
 * GET only shows a confirmation page; the action runs on POST. Mail security
 * gateways and link scanners pre-fetch every URL in a message, so a GET that
 * released mail would release everything in every digest.
 *
 * @Route("/q")
 */
class QuarantineActionController extends Controller
{
    /**
     * @Route("/{token}", name="antispam_quarantine_action", requirements={"token"="[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"}, methods={"GET","POST"})
     */
    public function actionAction(Request $request, $token)
    {
        $tokens = $this->get('antispam.digest_token');
        // With a published default secret anyone could mint tokens.
        $data = $tokens->usesDefaultSecret() ? null : $tokens->verify($token);
        if (!$data) {
            return $this->page('invalid', null, null, Response::HTTP_GONE);
        }

        if (!$request->isMethod('POST')) {
            return $this->page('confirm', $data, null);
        }

        $quarantine = $this->get('antispam.quarantine');
        try {
            if ($data['action'] === DigestTokenService::ACTION_DELETE) {
                $result = $quarantine->delete($data['mailbox'], $data['id']);
            } else {
                $result = $quarantine->release($data['mailbox'], $data['id'], $data['action'] === DigestTokenService::ACTION_WHITELIST);
            }
        } catch (\Throwable $e) {
            $result = ['success' => false, 'message' => 'Nie udało się połączyć z serwerem poczty. Spróbuj ponownie później.'];
        }

        return $this->page('done', $data, $result, $result['success'] ? 200 : 409);
    }

    private function page($state, $data, $result, $status = 200)
    {
        $response = $this->render('@Antispam/Digest/action.html.twig', [
            'state' => $state,
            'data' => $data,
            'result' => $result,
        ]);
        $response->setStatusCode($status);
        // Tokens are credentials: keep them out of caches and Referer headers.
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Robots-Tag', 'noindex, nofollow');
        return $response;
    }
}
