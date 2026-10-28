<?php

namespace AntispamBundle\Security\TwoFactor;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

/**
 * QR code of the otpauth:// URI, rendered locally as SVG (bacon/bacon-qr-code)
 * and embedded as a data: URI - the secret never leaves the server and the
 * CSP (img-src 'self' data:) needs no change.
 */
class QrCodeRenderer
{
    public function svgDataUri(string $text, int $size = 220): string
    {
        $svg = (new Writer(new ImageRenderer(new RendererStyle($size, 2), new SvgImageBackEnd())))->writeString($text);
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }
}
