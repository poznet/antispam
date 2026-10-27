<?php

namespace AntispamBundle\Services;

/**
 * Builds and parses the c-client flag string (`/imap/ssl/novalidate-cert`...)
 * stored in Account::$imapFlags, so the account form can offer clickable
 * SSL/TLS options instead of a free text field.
 *
 * Encryption modes map to c-client flags:
 *   ssl      -> /ssl    implicit TLS from the first byte (IMAPS, port 993)
 *   starttls -> /tls    plain connection upgraded with STARTTLS, required (port 143)
 *   auto     -> (none)  c-client uses STARTTLS when the server offers it, else plain
 *   none     -> /notls  never encrypt (password travels in clear text)
 */
final class ImapFlags
{
    const ENCRYPTION_SSL = 'ssl';
    const ENCRYPTION_STARTTLS = 'starttls';
    const ENCRYPTION_AUTO = 'auto';
    const ENCRYPTION_NONE = 'none';

    const ENCRYPTIONS = [self::ENCRYPTION_SSL, self::ENCRYPTION_STARTTLS, self::ENCRYPTION_AUTO, self::ENCRYPTION_NONE];

    const DEFAULT_FLAGS = '/imap/ssl';

    /** Flags the form has a control for; anything else makes the string "custom". */
    const OPTION_FLAGS = ['secure' => 'secure', 'norsh' => 'norsh', 'debug' => 'debug'];

    public static function defaultOptions()
    {
        return [
            'encryption' => self::ENCRYPTION_SSL,
            'validate_cert' => true,
            'secure' => false,
            'norsh' => false,
            'debug' => false,
            'custom' => false,
        ];
    }

    public static function defaultPort($encryption)
    {
        return $encryption === self::ENCRYPTION_SSL ? 993 : 143;
    }

    /**
     * @param array $options encryption, validate_cert, secure, norsh, debug
     */
    public static function build(array $options)
    {
        $encryption = in_array($options['encryption'] ?? null, self::ENCRYPTIONS, true)
            ? $options['encryption'] : self::ENCRYPTION_SSL;

        $flags = '/imap';
        $flags .= match ($encryption) {
            self::ENCRYPTION_SSL => '/ssl',
            self::ENCRYPTION_STARTTLS => '/tls',
            self::ENCRYPTION_NONE => '/notls',
            default => '',
        };
        // Certificate validation is c-client's default; only the opt-out is written.
        if ($encryption !== self::ENCRYPTION_NONE && empty($options['validate_cert'])) {
            $flags .= '/novalidate-cert';
        }
        foreach (self::OPTION_FLAGS as $key => $flag) {
            if (!empty($options[$key])) {
                $flags .= '/' . $flag;
            }
        }

        return $flags;
    }

    /**
     * Reads a stored flag string back into form options. Flags the form cannot
     * express (`/readonly`, `/user=...`, contradicting modes) set `custom`, so
     * the form shows the raw string instead of silently dropping them.
     */
    public static function parse($flags)
    {
        $options = self::defaultOptions();
        $options['encryption'] = self::ENCRYPTION_AUTO;
        $modes = [];

        $tokens = array_filter(explode('/', strtolower(trim((string)$flags))), 'strlen');
        if (!$tokens) {
            return self::defaultOptions();
        }
        foreach ($tokens as $token) {
            switch ($token) {
                case 'imap':
                case 'imap4':
                case 'imap4rev1':
                case 'service=imap':
                    break;
                case 'ssl':
                    $modes[] = self::ENCRYPTION_SSL;
                    break;
                case 'tls':
                    $modes[] = self::ENCRYPTION_STARTTLS;
                    break;
                case 'notls':
                    $modes[] = self::ENCRYPTION_NONE;
                    break;
                case 'novalidate-cert':
                    $options['validate_cert'] = false;
                    break;
                case 'validate-cert':
                    $options['validate_cert'] = true;
                    break;
                default:
                    $key = array_search($token, self::OPTION_FLAGS, true);
                    if ($key === false) {
                        $options['custom'] = true;
                    } else {
                        $options[$key] = true;
                    }
            }
        }

        $modes = array_unique($modes);
        if (count($modes) === 1) {
            $options['encryption'] = $modes[0];
        } elseif (count($modes) > 1) {
            // e.g. /ssl/notls: c-client would pick one; let the admin see it.
            $options['custom'] = true;
            $options['encryption'] = in_array(self::ENCRYPTION_SSL, $modes, true) ? self::ENCRYPTION_SSL : $modes[0];
        }

        return $options;
    }

    /**
     * Raw flags typed by hand: keep only characters c-client flags use, so a
     * stray `}` or space cannot break the `{host:port/flags}` mailbox string.
     */
    public static function sanitize($flags)
    {
        $flags = preg_replace('~[^A-Za-z0-9/=._@+-]~', '', trim((string)$flags));
        if ($flags === '') {
            return self::DEFAULT_FLAGS;
        }
        return $flags[0] === '/' ? $flags : '/' . $flags;
    }

    /**
     * Account form input -> stored flag string. `imap_flags_custom` keeps the
     * hand-typed string; otherwise it is built from the `imap_tls` options.
     */
    public static function fromFormData(array $data)
    {
        if (!empty($data['imap_flags_custom']) || !isset($data['imap_tls']) || !is_array($data['imap_tls'])) {
            return self::sanitize($data['imap_flags'] ?? '');
        }
        return self::build($data['imap_tls']);
    }
}
