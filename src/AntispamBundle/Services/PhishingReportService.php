<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\PhishingReport;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Phishing reports from the mail client plugins: stores the full message and
 * turns it into what an admin needs to judge it and build filters - decoded
 * headers, authentication results, links (with text/target mismatches),
 * attachments with hashes and a list of red flags.
 */
class PhishingReportService
{
    /** Full source incl. attachments; must fit post_max_size once base64-encoded. */
    const MAX_RAW_BYTES = 10485760; // 10 MiB
    const MAX_LINKS = 300;
    /**
     * Stored phishing sources per mailbox. Any plugin user can report, so
     * without a cap one token could fill the disk (30 x 10 MiB per hour).
     */
    const MAX_STORED_BYTES_PER_ACCOUNT = 524288000; // 500 MiB
    /** ...and in total, so several accounts cannot fill the disk together. */
    const MAX_STORED_BYTES_TOTAL = 5368709120; // 5 GiB

    const CLIENTS = ['thunderbird', 'outlook', 'applemail'];

    /** Free mailbox providers: blocking the whole domain would block everyone. */
    const FREEMAIL_DOMAINS = [
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com',
        'icloud.com', 'me.com', 'aol.com', 'gmx.com', 'gmx.net', 'proton.me', 'protonmail.com',
        'wp.pl', 'o2.pl', 'onet.pl', 'onet.eu', 'op.pl', 'poczta.onet.pl', 'interia.pl', 'interia.eu',
        'poczta.fm', 'gazeta.pl', 'tlen.pl', 'vp.pl', 'autograf.pl', 'buziaczek.pl', 'int.pl',
    ];

    const RISKY_EXTENSIONS = [
        'exe', 'scr', 'com', 'bat', 'cmd', 'pif', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'msi', 'lnk', 'iso',
        'img', 'vhd', 'jar', 'ps1', 'docm', 'xlsm', 'pptm', 'html', 'htm', 'svg', 'zip', 'rar', '7z', 'cab',
    ];

    public function __construct(private EntityManagerInterface $em, private ?CertHoleService $cert = null)
    {
    }

    /**
     * Store a report. The same message reported again by the same account
     * only bumps the counter.
     *
     * @return array{id:int, duplicate:bool}
     *
     * @throws \OverflowException when the account's storage quota is used up
     */
    public function submit($raw, Account $account, $client = null, $clientIp = null, $truncated = false)
    {
        $repo = $this->em->getRepository(PhishingReport::class);
        $existing = $repo->findOneBy(['accountEmail' => $account->getEmail(), 'sha256' => hash('sha256', (string)$raw)]);
        if ($existing) {
            $existing->reportedAgain();
            $this->em->flush();
            return ['id' => $existing->getId(), 'duplicate' => true];
        }

        if ($repo->storedBytes($account->getEmail()) + strlen((string)$raw) > self::MAX_STORED_BYTES_PER_ACCOUNT
            || $repo->storedBytes() + strlen((string)$raw) > self::MAX_STORED_BYTES_TOTAL) {
            throw new \OverflowException('phishing report storage quota exceeded');
        }

        $msg = new RawMessageParser($raw);
        $report = (new PhishingReport())
            ->setRaw($raw)
            ->setAccountEmail($account->getEmail())
            ->setClient(in_array($client, self::CLIENTS, true) ? $client : null)
            ->setClientIp($clientIp ?: null)
            ->setSender($msg->getFromAddress() ?: null)
            ->setSenderName($msg->getFromName() ?: null)
            ->setReplyTo($msg->getAddress('reply-to') ?: null)
            ->setReturnPath($msg->getAddress('return-path') ?: null)
            ->setSubject($msg->getSubject() ?: null)
            ->setMessageId(trim($msg->getHeader('message-id'), " <>") ?: null)
            ->setConnectingIp($msg->getConnectingIp())
            ->setTruncated($truncated);
        $this->em->persist($report);
        $this->em->flush();

        $repo->purgeOlderThan(new \DateTime('-' . PhishingReport::RETENTION_DAYS . ' days'));
        return ['id' => $report->getId(), 'duplicate' => false];
    }

    /** Everything the detail page shows, derived from the stored source. */
    public function analyze(PhishingReport $report)
    {
        $msg = new RawMessageParser($report->getRaw());
        $parts = $msg->getParts();
        $fromHost = mb_scrub($msg->getFromHost(), 'UTF-8');

        $auth = [];
        foreach (array_merge($msg->getHeaders('authentication-results'), $msg->getHeaders('arc-authentication-results')) as $line) {
            if (preg_match_all('/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/i', $line, $m, PREG_SET_ORDER)) {
                foreach ($m as $hit) {
                    $auth[strtolower($hit[1])] ??= strtolower($hit[2]);
                }
            }
        }
        if (!isset($auth['spf']) && ($spf = $msg->getHeader('received-spf')) !== '' && preg_match('/^\s*([a-z]+)/i', $spf, $m)) {
            $auth['spf'] = strtolower($m[1]);
        }
        $dkimDomains = [];
        foreach ($msg->getHeaders('dkim-signature') as $sig) {
            if (preg_match('/\bd\s*=\s*([^;\s]+)/i', $sig, $m)) {
                $dkimDomains[] = strtolower($m[1]);
            }
        }

        $links = self::links($parts['html'], $parts['text']);
        $attachments = [];
        foreach ($parts['attachments'] as $att) {
            $ext = strtolower(pathinfo((string)$att['filename'], PATHINFO_EXTENSION));
            $attachments[] = [
                'filename' => $att['filename'] !== '' ? $att['filename'] : '(bez nazwy)',
                'type' => $att['type'] ?? '',
                'size' => strlen($att['data']),
                'sha256' => hash('sha256', $att['data']),
                'risky' => in_array($ext, self::RISKY_EXTENSIONS, true),
            ];
        }

        $hosts = [];
        foreach ($links as $l) {
            if ($l['host'] !== '') {
                $hosts[$l['host']] = ($hosts[$l['host']] ?? 0) + 1;
            }
        }
        arsort($hosts);

        // Shown whether or not the CERT filter is enabled - it only needs a synced list.
        $certListed = [];   // listed domains
        $certHosts = [];    // link hosts that are, or are under, a listed domain
        if ($this->cert) {
            $byHost = [];
            foreach (array_merge([$fromHost, self::domainOf((string)$report->getReplyTo()), self::domainOf((string)$report->getReturnPath())], array_keys($hosts)) as $h) {
                $byHost[$h] = CertHoleService::candidates($h);
            }
            $candidates = array_merge([], ...array_values($byHost));
            $listed = $candidates ? $this->cert->findListed($candidates) : [];
            $certListed = array_keys($listed);
            foreach ($byHost as $h => $cands) {
                if (array_intersect_key(array_flip($cands), $listed)) {
                    $certHosts[] = $h;
                }
            }
        }

        $flags = self::flags($report, $fromHost, $auth, $dkimDomains, $links, $attachments);
        if ($certListed) {
            array_unshift($flags, 'Domena z Listy Ostrzeżeń CERT Polska: ' . implode(', ', $certListed));
        }

        return [
            'headers' => $msg->getHeaderList(),
            'from_host' => $fromHost,
            'date' => $msg->getHeader('date'),
            'mailer' => $msg->getHeader('x-mailer') ?: $msg->getHeader('user-agent'),
            'auth' => $auth,
            'dkim_domains' => array_values(array_unique($dkimDomains)),
            'received' => $msg->getHeaders('received'),
            'links' => $links,
            'link_hosts' => $hosts,
            'attachments' => $attachments,
            'text' => $parts['text'] !== '' ? $parts['text'] : $msg->getBodyText(),
            'html' => $parts['html'],
            'flags' => $flags,
            'cert_hosts' => $certHosts,
            'freemail' => self::isFreemail($fromHost),
        ];
    }

    public static function isFreemail($domain)
    {
        return in_array(strtolower((string)$domain), self::FREEMAIL_DOMAINS, true);
    }

    public static function domainOf($address)
    {
        $p = strrpos((string)$address, '@');
        return $p === false ? '' : strtolower(substr($address, $p + 1));
    }

    /**
     * Unique links with their host; `mismatch` when the visible text is itself
     * a URL/domain that differs from where the link really goes.
     */
    public static function links($html, $text)
    {
        $out = [];
        foreach (UrlAnalyzer::extractLinks($html, $text) as $l) {
            $href = $l['href'];
            if (isset($out[$href]) || !preg_match('~^https?://~i', $href)) {
                if (isset($out[$href]) && $l['text'] !== null && $out[$href]['text'] === null) {
                    $out[$href]['text'] = $l['text'];
                }
                continue;
            }
            $host = UrlAnalyzer::hostOf($href);
            $shown = '';
            if ($l['text'] !== null && preg_match('~^(?:https?://)?([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})(?:[/:?#]|$)~i', trim($l['text']), $m)) {
                $shown = strtolower($m[1]);
            }
            $out[$href] = [
                'href' => $href,
                'text' => $l['text'],
                'host' => $host,
                'ip' => (bool)filter_var(trim($host, '[]'), FILTER_VALIDATE_IP),
                'mismatch' => $shown !== '' && $host !== '' && $shown !== $host && !str_ends_with($host, '.' . $shown),
            ];
            if (count($out) >= self::MAX_LINKS) {
                break;
            }
        }
        return array_values($out);
    }

    /** Red flags, most telling first. */
    private static function flags(PhishingReport $r, $fromHost, array $auth, array $dkimDomains, array $links, array $attachments)
    {
        $flags = [];
        foreach (['spf', 'dkim', 'dmarc'] as $k) {
            if (isset($auth[$k]) && !in_array($auth[$k], ['pass', 'none', 'neutral'], true)) {
                $flags[] = strtoupper($k) . ': ' . $auth[$k];
            }
        }
        if ($fromHost !== '' && $dkimDomains && !array_filter($dkimDomains, fn ($d) => $d === $fromHost || str_ends_with($fromHost, '.' . $d) || str_ends_with($d, '.' . $fromHost))) {
            $flags[] = 'Podpis DKIM innej domeny (' . implode(', ', $dkimDomains) . ') niż nadawca (' . $fromHost . ')';
        }
        if ($r->getReplyTo() && self::domainOf($r->getReplyTo()) !== $fromHost) {
            $flags[] = 'Odpowiedź idzie na inny adres: ' . $r->getReplyTo();
        }
        if ($r->getReturnPath() && $fromHost !== '' && self::domainOf($r->getReturnPath()) !== $fromHost
            && !str_ends_with(self::domainOf($r->getReturnPath()), '.' . $fromHost)) {
            $flags[] = 'Return-Path z innej domeny: ' . $r->getReturnPath();
        }
        $name = (string)$r->getSenderName();
        if ($name !== '' && preg_match('/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', $name, $m) && strtolower($m[0]) !== $r->getSender()) {
            $flags[] = 'Nazwa nadawcy udaje inny adres: ' . $name;
        }
        $mismatch = count(array_filter($links, fn ($l) => $l['mismatch']));
        if ($mismatch) {
            $flags[] = 'Linki prowadzą gdzie indziej, niż pokazuje ich tekst: ' . $mismatch;
        }
        if (array_filter($links, fn ($l) => $l['ip'])) {
            $flags[] = 'Linki do adresu IP zamiast domeny';
        }
        foreach ($attachments as $a) {
            if ($a['risky']) {
                $flags[] = 'Ryzykowny załącznik: ' . $a['filename'];
            }
        }
        if ($r->isTruncated()) {
            $flags[] = 'Wtyczka obcięła wiadomość (limit rozmiaru) - część załączników może brakować';
        }
        return $flags;
    }
}
