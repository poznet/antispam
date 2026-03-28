<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Table(name="antispam_scan_log")
 * @ORM\Entity()
 */
class ScanLog
{
    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\ManyToOne(targetEntity="AntispamBundle\Entity\Account")
     * @ORM\JoinColumn(name="account_id", referencedColumnName="id", onDelete="CASCADE")
     */
    private $account;

    /**
     * @ORM\Column(name="scan_type", type="string", length=10)
     */
    private $scanType;

    /**
     * @ORM\Column(name="scanned_at", type="datetime")
     */
    private $scannedAt;

    /**
     * @ORM\Column(name="duration_ms", type="integer", nullable=true)
     */
    private $durationMs;

    /**
     * @ORM\Column(name="total_messages", type="integer")
     */
    private $totalMessages = 0;

    /**
     * @ORM\Column(name="checked", type="integer")
     */
    private $checked = 0;

    /**
     * @ORM\Column(name="skipped", type="integer")
     */
    private $skipped = 0;

    /**
     * @ORM\Column(name="whitelisted", type="integer")
     */
    private $whitelisted = 0;

    /**
     * @ORM\Column(name="blacklisted", type="integer")
     */
    private $blacklisted = 0;

    /**
     * @ORM\Column(name="moved_to_spam", type="integer")
     */
    private $movedToSpam = 0;

    /**
     * @ORM\Column(name="success", type="boolean")
     */
    private $success = true;

    /**
     * @ORM\Column(name="error_message", type="text", nullable=true)
     */
    private $errorMessage;

    /**
     * @ORM\Column(name="result_json", type="text", nullable=true)
     */
    private $resultJson;

    public function getId() { return $this->id; }

    public function getAccount() { return $this->account; }
    public function setAccount(Account $account) { $this->account = $account; return $this; }

    public function getScanType() { return $this->scanType; }
    public function setScanType($scanType) { $this->scanType = $scanType; return $this; }

    public function getScannedAt() { return $this->scannedAt; }
    public function setScannedAt(\DateTime $scannedAt) { $this->scannedAt = $scannedAt; return $this; }

    public function getDurationMs() { return $this->durationMs; }
    public function setDurationMs($durationMs) { $this->durationMs = $durationMs; return $this; }

    public function getTotalMessages() { return $this->totalMessages; }
    public function setTotalMessages($totalMessages) { $this->totalMessages = $totalMessages; return $this; }

    public function getChecked() { return $this->checked; }
    public function setChecked($checked) { $this->checked = $checked; return $this; }

    public function getSkipped() { return $this->skipped; }
    public function setSkipped($skipped) { $this->skipped = $skipped; return $this; }

    public function getWhitelisted() { return $this->whitelisted; }
    public function setWhitelisted($whitelisted) { $this->whitelisted = $whitelisted; return $this; }

    public function getBlacklisted() { return $this->blacklisted; }
    public function setBlacklisted($blacklisted) { $this->blacklisted = $blacklisted; return $this; }

    public function getMovedToSpam() { return $this->movedToSpam; }
    public function setMovedToSpam($movedToSpam) { $this->movedToSpam = $movedToSpam; return $this; }

    public function getSuccess() { return $this->success; }
    public function setSuccess($success) { $this->success = $success; return $this; }

    public function getErrorMessage() { return $this->errorMessage; }
    public function setErrorMessage($errorMessage) { $this->errorMessage = $errorMessage; return $this; }

    public function getResultJson() { return $this->resultJson; }
    public function setResultJson($resultJson) { $this->resultJson = $resultJson; return $this; }

    public static function fromScanResult(Account $account, array $result, $durationMs = null)
    {
        $log = new self();
        $log->setAccount($account);
        $log->setScanType($account->getConnectionType());
        $log->setScannedAt(new \DateTime());
        $log->setDurationMs($durationMs);
        $log->setTotalMessages($result['total'] ?? 0);
        $log->setChecked($result['checked'] ?? 0);
        $log->setSkipped($result['skipped'] ?? 0);
        $log->setWhitelisted($result['whitelisted'] ?? 0);
        $log->setBlacklisted($result['blacklisted'] ?? 0);
        $log->setMovedToSpam($result['moved_to_spam'] ?? 0);
        $log->setSuccess(true);
        $log->setResultJson(json_encode($result));
        return $log;
    }

    public static function fromError(Account $account, $errorMessage, $durationMs = null)
    {
        $log = new self();
        $log->setAccount($account);
        $log->setScanType($account->getConnectionType());
        $log->setScannedAt(new \DateTime());
        $log->setDurationMs($durationMs);
        $log->setSuccess(false);
        $log->setErrorMessage($errorMessage);
        return $log;
    }
}
