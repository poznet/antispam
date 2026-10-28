<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\PhishingForwardService;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Services\ScoringService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Phishing attempts reported from the mail client plugins: list, full message
 * inspection (headers, links, attachments, red flags), status / note, quick
 * blocking rules for the reporting mailbox and .eml download (e.g. for CERT).
 */
#[Route('/phishing')]
class PhishingController extends AbstractController
{
    private const PER_PAGE = 50;

    public function __construct(
        private EntityManagerInterface $em,
        private PhishingReportService $phishing,
        private RetroactiveSpamService $retroactive,
        private ScoringService $scoring,
        private PhishingForwardService $forwarder,
    ) {
    }

    #[Route('/', name: 'antispam_phishing_index', methods: ['GET'])]
    #[Template('@Antispam/Phishing/index.html.twig')]
    public function indexAction(Request $request)
    {
        $repo = $this->em->getRepository(PhishingReport::class);
        $accounts = $repo->distinctAccounts();
        $filters = [
            'status' => array_key_exists($request->query->get('status'), PhishingReport::STATUSES) ? $request->query->get('status') : null,
            'account' => in_array($request->query->get('account'), $accounts, true) ? $request->query->get('account') : null,
            'q' => mb_substr(trim((string)$request->query->get('q')), 0, 100),
        ];
        $page = max(1, $request->query->getInt('page', 1));
        $list = $repo->findList($filters, self::PER_PAGE, ($page - 1) * self::PER_PAGE);

        return [
            'rows' => $list['rows'],
            'total' => $list['total'],
            'page' => $page,
            'pages' => max(1, (int)ceil($list['total'] / self::PER_PAGE)),
            'filters' => $filters,
            'query' => array_filter($filters),
            'accounts' => $accounts,
            'counts' => $repo->countByStatus(),
            'statuses' => PhishingReport::STATUSES,
            'forward_errors' => $this->forwarder->configurationErrors(),
            'forward_recipients' => $this->forwarder->getSettings()['recipients'],
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ];
    }

    #[Route('/{id}', name: 'antispam_phishing_show', requirements: ['id' => '\d+'], methods: ['GET'])]
    #[Template('@Antispam/Phishing/show.html.twig')]
    public function showAction(int $id)
    {
        $report = $this->find($id);
        return [
            'report' => $report,
            'a' => $this->phishing->analyze($report),
            'statuses' => PhishingReport::STATUSES,
            'sender_blocked' => $report->getSender() && $this->em->getRepository(EmailBlacklist::class)->findOneBy([
                'email' => $report->getAccountEmail(), 'blacklistemail' => $report->getSender(),
            ]) !== null,
            'forwarded_before' => $this->forwarder->previouslyForwarded($report),
            'forward_errors' => $this->forwarder->configurationErrors(),
            'forward_settings' => $this->forwarder->getSettings(),
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ];
    }

    #[Route('/{id}/update', name: 'antispam_phishing_update', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function updateAction(int $id, Request $request)
    {
        $this->checkToken($request);
        $report = $this->find($id);
        $status = (string)$request->request->get('status');
        if (array_key_exists($status, PhishingReport::STATUSES)) {
            $report->setStatus($status);
        }
        $report->setNote(mb_substr((string)$request->request->get('note'), 0, 5000));
        $this->em->flush();
        $this->addFlash('success', 'Zapisano.');
        return $this->redirectToRoute('antispam_phishing_show', ['id' => $id]);
    }

    /**
     * Block the sender address or its whole domain for the reporting mailbox
     * (scored at the spam threshold) and move matching INBOX mail to SPAM.
     */
    #[Route('/{id}/block', name: 'antispam_phishing_block', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function blockAction(int $id, Request $request)
    {
        $this->checkToken($request);
        $report = $this->find($id);
        $what = (string)$request->request->get('what');
        $owner = $report->getAccountEmail();
        $score = max(10, $this->scoring->getSpamThreshold());
        $rule = null;

        if ($what === 'sender' && $report->getSender()) {
            $repo = $this->em->getRepository(EmailBlacklist::class);
            if (!$repo->findOneBy(['email' => $owner, 'blacklistemail' => $report->getSender()])) {
                $rule = (new EmailBlacklist())->setEmail($owner)->setBlacklistemail($report->getSender())
                    ->setPatternType(EmailBlacklist::PATTERN_EXACT)->setCounter(0);
                $rule->setScore($score);
            }
        } elseif ($what === 'domain') {
            $domain = PhishingReportService::domainOf((string)$report->getSender());
            if ($domain === '' || PhishingReportService::isFreemail($domain)) {
                $this->addFlash('danger', 'Tej domeny nie można zablokować w całości (pusta albo darmowa poczta).');
                return $this->redirectToRoute('antispam_phishing_show', ['id' => $id]);
            }
            if (!$this->em->getRepository(Blacklist::class)->findOneBy(['email' => $owner, 'host' => $domain])) {
                $rule = (new Blacklist())->setEmail($owner)->setHost($domain)
                    ->setPatternType(Blacklist::PATTERN_EXACT)->setScore($score);
            }
        } else {
            throw $this->createNotFoundException();
        }

        if ($rule === null) {
            $this->addFlash('info', 'Ta reguła już istnieje.');
        } else {
            $this->em->persist($rule);
            $this->em->flush();
            $this->addFlash('success', 'Dodano regułę blacklisty dla ' . $owner . '.');
            $summary = RetroactiveSpamService::describe($this->retroactive->applyRule($rule));
            if ($summary) {
                $this->addFlash('info', $summary);
            }
        }
        return $this->redirectToRoute('antispam_phishing_show', ['id' => $id]);
    }

    /** Original message as .eml - never rendered by the browser. */
    #[Route('/{id}/eml', name: 'antispam_phishing_eml', requirements: ['id' => '\d+'], methods: ['GET'])]
    public function emlAction(int $id)
    {
        $report = $this->find($id);
        $response = new Response($report->getRaw());
        $response->headers->set('Content-Type', 'message/rfc822');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Content-Security-Policy', "default-src 'none'; sandbox");
        $response->headers->set('Content-Disposition', $response->headers->makeDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'phishing-' . $id . '.eml'));
        return $response;
    }

    /**
     * Forward the original message to CERT Polska / the SOC address. A report
     * (or another copy of the same message) that was already sent needs an
     * explicit resend=1 - the button asks for confirmation first.
     */
    #[Route('/{id}/forward', name: 'antispam_phishing_forward', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function forwardAction(int $id, Request $request)
    {
        $this->checkToken($request);
        $report = $this->find($id);
        $resend = $request->request->get('resend') === '1';

        $before = $this->forwarder->previouslyForwarded($report);
        if ($before && !$resend) {
            $this->addFlash('warning', sprintf('Ta wiadomość została już wysłana (%s do %s). Potwierdź ponowną wysyłkę.',
                $before->getForwardedAt()->format('Y-m-d H:i'), $before->getForwardedTo()));
            return $this->redirectToRoute('antispam_phishing_show', ['id' => $id]);
        }

        $result = $this->forwarder->forward($report, $resend);
        if ($result['status'] === 'sent') {
            $this->addFlash('success', 'Wysłano zgłoszenie do ' . $report->getForwardedTo() . '.');
        } elseif ($result['status'] === 'failed') {
            $this->addFlash('danger', 'Nie udało się wysłać: ' . $result['error']);
        } else {
            $this->addFlash('warning', 'Nie wysłano: ' . $result['error']);
        }
        return $this->redirectToRoute('antispam_phishing_show', ['id' => $id]);
    }

    /**
     * Forward the reports selected on the list. Already forwarded messages
     * (also copies reported by another mailbox) and false positives are
     * skipped - resending is only possible one by one, with confirmation.
     */
    #[Route('/forward', name: 'antispam_phishing_forward_bulk', methods: ['POST'])]
    public function forwardBulkAction(Request $request)
    {
        $this->checkToken($request);
        $ids = array_slice(array_unique(array_filter(array_map('intval', (array)$request->request->all('ids')))), 0, self::PER_PAGE);
        if (!$ids) {
            $this->addFlash('warning', 'Nie zaznaczono żadnego zgłoszenia.');
            return $this->redirectToRoute('antispam_phishing_index');
        }

        $counts = ['sent' => 0, 'failed' => 0, 'skipped' => 0];
        $errors = [];
        $sent = [];
        foreach ($ids as $id) {
            $report = $this->em->getRepository(PhishingReport::class)->find($id);
            if (!$report) {
                continue;
            }
            if (isset($sent[$report->getSha256()])) {
                $counts['skipped']++;
                continue;
            }
            $result = $this->forwarder->forward($report);
            $counts[$result['status']]++;
            if ($result['status'] === 'sent') {
                $sent[$report->getSha256()] = true;
            } elseif ($result['error']) {
                $errors[$result['error']] = '#' . $id . ': ' . $result['error'];
            }
        }

        $this->addFlash($counts['failed'] ? 'danger' : ($counts['sent'] ? 'success' : 'warning'), sprintf(
            'Wysłano: %d, pominięto: %d, błędy: %d.', $counts['sent'], $counts['skipped'], $counts['failed']
        ));
        foreach (array_slice($errors, 0, 5) as $e) {
            $this->addFlash('info', $e);
        }
        return $this->redirectToRoute('antispam_phishing_index');
    }

    #[Route('/forward-settings', name: 'antispam_phishing_forward_settings', methods: ['GET', 'POST'])]
    #[Template('@Antispam/Phishing/forward_settings.html.twig')]
    public function forwardSettingsAction(Request $request)
    {
        $settings = $this->forwarder->getSettings();
        $errors = [];
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('phishing_forward_settings', (string)$request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
            }
            [$input, $errors] = $this->forwarder->validateSettings($request->request->all('config'));
            if (!$errors) {
                $this->forwarder->saveSettings($input);
                $this->addFlash('success', 'Zapisano ustawienia przekazywania.');
                return $this->redirectToRoute('antispam_phishing_forward_settings');
            }
            // Show what the admin typed, with the errors.
            $settings = $input + $settings;
        }

        return [
            'settings' => $settings,
            'errors' => $errors,
            'status_errors' => $errors ? [] : $this->forwarder->configurationErrors(),
            'default_recipient' => PhishingForwardService::DEFAULT_RECIPIENT,
            'default_note' => PhishingForwardService::DEFAULT_NOTE,
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ];
    }

    #[Route('/{id}/delete', name: 'antispam_phishing_delete', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function deleteAction(int $id, Request $request)
    {
        $this->checkToken($request);
        $this->em->remove($this->find($id));
        $this->em->flush();
        $this->addFlash('success', 'Usunięto zgłoszenie.');
        return $this->redirectToRoute('antispam_phishing_index');
    }

    private function find(int $id): PhishingReport
    {
        $report = $this->em->getRepository(PhishingReport::class)->find($id);
        if (!$report) {
            throw $this->createNotFoundException('Nie ma takiego zgłoszenia');
        }
        return $report;
    }

    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('phishing', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
