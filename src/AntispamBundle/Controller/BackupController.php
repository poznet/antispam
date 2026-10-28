<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\Backup\BackupExporter;
use AntispamBundle\Services\Backup\BackupFormat;
use AntispamBundle\Services\Backup\BackupImporter;
use AntispamBundle\Services\Backup\InvalidBackupException;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * "Kopia zapasowa" (ROLE_ADMIN): download the configuration backup and
 * restore one in two steps - upload + dry-run preview, then apply. The
 * uploaded file waits for the second step in var/backup-import (0600, random
 * name bound to the session, removed after use or after an hour).
 * See docs/backup.md.
 */
#[Route('/backup')]
#[IsGranted('ROLE_ADMIN')]
class BackupController extends AbstractController
{
    use AuditTrait;

    public const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
    private const SESSION_KEY = 'backup_import';
    private const PENDING_TTL = 3600;

    public function __construct(
        private BackupExporter $exporter,
        private BackupImporter $importer,
        private UserPasswordHasherInterface $hasher,
        #[Autowire('%kernel.project_dir%/var/backup-import')] private string $pendingDir,
    ) {
    }

    #[Route('/', name: 'antispam_backup_index', methods: ['GET'])]
    #[Template('@Antispam/Backup/index.html.twig')]
    public function indexAction()
    {
        return [
            'sections' => BackupFormat::SECTIONS,
            'max_upload_mb' => self::MAX_UPLOAD_BYTES / 1048576,
            'zip_available' => class_exists(\ZipArchive::class),
        ];
    }

    #[Route('/export', name: 'antispam_backup_export', methods: ['POST'])]
    public function exportAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('backup_export', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
            return $this->redirectToRoute('antispam_backup_index');
        }
        $withSecrets = $request->request->getBoolean('include_secrets');
        if ($withSecrets) {
            $user = $this->getUser();
            if (!$request->request->getBoolean('confirm_secrets')) {
                $this->addFlash('danger', 'Zaznacz potwierdzenie, że plik będzie zawierał hasła i klucze API.');
                return $this->redirectToRoute('antispam_backup_index');
            }
            if (!$user instanceof PasswordAuthenticatedUserInterface
                || !$this->hasher->isPasswordValid($user, (string)$request->request->get('password'))) {
                $this->addFlash('danger', 'Nieprawidłowe hasło - kopia z sekretami wymaga ponownego podania hasła administratora.');
                return $this->redirectToRoute('antispam_backup_index');
            }
        }

        $json = BackupFormat::encode($this->exporter->export($withSecrets));
        $zip = $request->request->get('format') === 'zip' && class_exists(\ZipArchive::class);
        $name = 'antispam-backup-' . date('Ymd-His') . ($withSecrets ? '-secrets' : '') . ($zip ? '.zip' : '.json');

        $this->audit('backup.export', targetType: 'backup', label: $name, details: ['secrets' => $withSecrets, 'format' => $zip ? 'zip' : 'json']);
        $response = new Response($zip ? BackupFormat::zip($json) : $json);
        $response->headers->set('Content-Type', $zip ? 'application/zip' : 'application/json; charset=UTF-8');
        $response->headers->set('Content-Disposition', $response->headers->makeDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $name));
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }

    #[Route('/import', name: 'antispam_backup_import', methods: ['POST'])]
    public function importPreviewAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('backup_import', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
            return $this->redirectToRoute('antispam_backup_index');
        }
        [$mode, $sections] = $this->options($request);
        if ($sections === null) {
            return $this->redirectToRoute('antispam_backup_index');
        }

        $file = $request->files->get('backup');
        if (!$file instanceof UploadedFile || !$file->isValid()) {
            $this->addFlash('danger', 'Wybierz plik kopii zapasowej (.json lub .zip)' . ($file instanceof UploadedFile ? ': ' . $file->getErrorMessage() : '.'));
            return $this->redirectToRoute('antispam_backup_index');
        }
        if ($file->getSize() > self::MAX_UPLOAD_BYTES) {
            $this->addFlash('danger', sprintf('Plik jest za duży (maks. %d MB).', self::MAX_UPLOAD_BYTES / 1048576));
            return $this->redirectToRoute('antispam_backup_index');
        }

        try {
            $data = BackupFormat::readFile($file->getPathname());
            $report = $this->importer->import($data, $sections, $mode, true, $this->getUser()?->getUserIdentifier());
        } catch (InvalidBackupException $e) {
            $this->addFlash('danger', 'Nieprawidłowy plik kopii: ' . $e->getMessage());
            return $this->redirectToRoute('antispam_backup_index');
        }

        $id = $this->storePending(BackupFormat::encode($data));
        $request->getSession()->set(self::SESSION_KEY, ['id' => $id, 'name' => mb_substr((string)$file->getClientOriginalName(), 0, 120), 'at' => time()]);

        return $this->render('@Antispam/Backup/preview.html.twig', [
            'report' => $report,
            'file_name' => $file->getClientOriginalName(),
            'pending_id' => $id,
            'mode' => $mode,
            'sections' => $sections,
        ]);
    }

    #[Route('/import/apply', name: 'antispam_backup_apply', methods: ['POST'])]
    public function importApplyAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('backup_apply', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
            return $this->redirectToRoute('antispam_backup_index');
        }
        $pending = $request->getSession()->get(self::SESSION_KEY);
        $id = (string)$request->request->get('pending_id');
        if (!is_array($pending) || !hash_equals((string)($pending['id'] ?? ''), $id) || time() - (int)($pending['at'] ?? 0) > self::PENDING_TTL) {
            $this->addFlash('danger', 'Podgląd importu wygasł lub nie pochodzi z tej sesji - wgraj plik ponownie.');
            return $this->redirectToRoute('antispam_backup_index');
        }
        [$mode, $sections] = $this->options($request);
        if ($sections === null) {
            return $this->redirectToRoute('antispam_backup_index');
        }
        if ($mode === BackupImporter::MODE_REPLACE && !$request->request->getBoolean('confirm_replace')) {
            $this->addFlash('danger', 'Tryb "zastąp" usuwa wpisy, których nie ma w pliku - zaznacz potwierdzenie.');
            return $this->redirectToRoute('antispam_backup_index');
        }

        $path = $this->pendingPath($id);
        try {
            $data = BackupFormat::readFile($path);
            $report = $this->importer->import($data, $sections, $mode, false, $this->getUser()?->getUserIdentifier());
        } catch (InvalidBackupException $e) {
            $this->addFlash('danger', 'Nieprawidłowy plik kopii: ' . $e->getMessage());
            return $this->redirectToRoute('antispam_backup_index');
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Import nie powiódł się, niczego nie zmieniono: ' . $e->getMessage());
            return $this->redirectToRoute('antispam_backup_index');
        } finally {
            @unlink($path);
            $request->getSession()->remove(self::SESSION_KEY);
        }

        $this->audit('backup.import', targetType: 'backup', details: ['mode' => $mode, 'sections' => $sections, 'created' => $report->total('created'), 'updated' => $report->total('updated'), 'deleted' => $report->total('deleted'), 'skipped' => $report->total('skipped')]);
        $this->addFlash('success', sprintf('Import zakończony (%s): dodano %d, zaktualizowano %d, usunięto %d, pominięto %d.',
            $mode === BackupImporter::MODE_REPLACE ? 'zastąp' : 'scal',
            $report->total('created'), $report->total('updated'), $report->total('deleted'), $report->total('skipped')));
        foreach (array_slice($report->getWarnings(), 0, 20) as $warning) {
            $this->addFlash('warning', $warning);
        }
        $this->addFlash('info', 'Agenci SSH dostaną nowe reguły po synchronizacji (Konta → Synchronizuj lub antispam:agent:sync <id konta>).');

        return $this->redirectToRoute('antispam_backup_index');
    }

    /** @return array{0: string, 1: string[]|null} mode and sections (null = invalid, flash added) */
    private function options(Request $request): array
    {
        $mode = (string)$request->request->get('mode', BackupImporter::MODE_MERGE);
        if (!in_array($mode, BackupImporter::MODES, true)) {
            $this->addFlash('danger', 'Nieznany tryb importu.');
            return [$mode, null];
        }
        $sections = array_values(array_intersect(BackupFormat::SECTIONS, array_map('strval', $request->request->all('sections'))));
        if (!$sections) {
            $this->addFlash('danger', 'Wybierz co najmniej jedną sekcję do importu.');
            return [$mode, null];
        }

        return [$mode, $sections];
    }

    private function storePending(string $json): string
    {
        if (!is_dir($this->pendingDir) && !@mkdir($this->pendingDir, 0700, true) && !is_dir($this->pendingDir)) {
            throw new \RuntimeException('Cannot create ' . $this->pendingDir);
        }
        foreach (glob($this->pendingDir . '/*.json') ?: [] as $old) {
            if (@filemtime($old) < time() - self::PENDING_TTL) {
                @unlink($old);
            }
        }
        $id = bin2hex(random_bytes(16));
        $path = $this->pendingPath($id);
        if (file_put_contents($path, $json) === false) {
            throw new \RuntimeException('Cannot store the uploaded backup');
        }
        @chmod($path, 0600);

        return $id;
    }

    private function pendingPath(string $id): string
    {
        if (!preg_match('/^[0-9a-f]{32}$/', $id)) {
            throw new InvalidBackupException('Invalid import id.');
        }

        return $this->pendingDir . '/' . $id . '.json';
    }
}
