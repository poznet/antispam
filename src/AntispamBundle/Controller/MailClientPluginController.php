<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\MailClientPluginBuilder;
use AntispamBundle\Services\PluginService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Downloads for Outlook and Apple Mail (the Thunderbird .xpi is in
 * PluginApiController). All of them use the same /api/plugin endpoints and
 * the same plugin.* settings.
 *
 * Public routes (security.yaml: ^/plugin/(download|outlook/|apple-mail/)).
 */
class MailClientPluginController extends AbstractController
{
    public function __construct(
        private PluginService $plugin,
        private MailClientPluginBuilder $builder,
    ) {
    }

    /** Outlook add-in manifest to sideload ("Add from file") or deploy centrally. */
    #[Route('/plugin/outlook/manifest.xml', name: 'antispam_plugin_outlook_manifest', methods: ['GET'], priority: 10)]
    public function outlookManifestAction(Request $request)
    {
        $this->assertEnabled();
        $base = $this->baseUrl($request);
        if (!MailClientPluginBuilder::isOutlookCompatible($base)) {
            return new Response(
                "Dodatek Outlook wymaga adresu HTTPS, a serwer jest widoczny jako $base.\n"
                . "Ustaw „Publiczny adres” (https://…) w Konfiguracja → Wtyczki pocztowe albo SYMFONY_TRUSTED_PROXIES.\n",
                409,
                ['Content-Type' => 'text/plain; charset=UTF-8']
            );
        }

        $response = new Response($this->builder->outlookManifest($base));
        $response->headers->set('Content-Type', 'application/xml; charset=UTF-8');
        $response->headers->set('Content-Disposition', $response->headers->makeDisposition(
            ResponseHeaderBag::DISPOSITION_ATTACHMENT,
            'antispam-outlook.xml'
        ));
        return $response;
    }

    /** Task pane files referenced by the manifest (loaded by Outlook in a web view). */
    #[Route('/plugin/outlook/{file}', name: 'antispam_plugin_outlook_asset', methods: ['GET'], requirements: ['file' => '[a-z]+\.(html|js|css)|icons/icon-\d+\.png'])]
    public function outlookAssetAction(string $file)
    {
        $this->assertEnabled();
        $asset = $this->builder->outlookAsset($file);
        if (!$asset) {
            throw $this->createNotFoundException();
        }

        $response = new BinaryFileResponse($asset['path']);
        $response->headers->set('Content-Type', $asset['type']);
        $response->setPublic();
        $response->setMaxAge(300);
        return $response;
    }

    /**
     * Source of the Apple Mail (MailKit) extension with the server URL set.
     * It must be built and signed in Xcode - no prebuilt binary is offered.
     */
    #[Route('/plugin/apple-mail/source.zip', name: 'antispam_plugin_applemail_source', methods: ['GET'])]
    public function appleMailSourceAction(Request $request)
    {
        $this->assertEnabled();
        if (!class_exists(\ZipArchive::class)) {
            return new Response('PHP zip extension is required to build the archive', 500);
        }

        $response = new BinaryFileResponse($this->builder->appleMailSourceZip($this->baseUrl($request)));
        $response->headers->set('Content-Type', 'application/zip');
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'antispam-apple-mail-source.zip');
        $response->deleteFileAfterSend(true);
        return $response;
    }

    private function assertEnabled(): void
    {
        if (!$this->plugin->isEnabled()) {
            throw $this->createNotFoundException('Mail client plugins are disabled');
        }
    }

    private function baseUrl(Request $request): string
    {
        return $this->plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath();
    }
}
