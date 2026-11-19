<?php

namespace AntispamBundle\Services;

/**
 * Complex rules ("Reguły złożone", docs/complex-rules.md): a tree of
 * conditions joined with AND / OR, e.g.
 *
 *     {"op": "and", "items": [
 *         {"field": "subject", "match": "contains", "value": "faktura"},
 *         {"field": "body", "match": "contains", "value": "przelew", "negate": true},
 *         {"op": "or", "items": [
 *             {"field": "from_domain", "match": "wildcard", "value": "*.ru"},
 *             {"field": "header", "header": "X-Mailer", "match": "regex", "value": "^php"}
 *         ]}
 *     ]}
 *
 * Pure and stateless. The same semantics are implemented by the Maildir agent
 * (complexRule*() in antispam-agent.php) and the Thunderbird plugin
 * (complexEval() in background.js) - keep the three in sync
 * (ComplexRuleEngineTest + AgentParityTest).
 *
 * Fields: see FIELDS / FIELD_META. mx_provider, mx_host and domain_age
 * need a DNS / RDAP lookup (SenderIntelService, cached); the plugin cannot do
 * them, so it leaves rules using them to the server.
 *
 * Matching: every value is lower-cased (UTF-8) with whitespace runs folded
 * to one space and trimmed, the pattern likewise (regex patterns are only
 * trimmed). Field with several values (to, reply_to, header, attachment): a
 * condition holds when any value matches; with "negate" when none does.
 */
final class ComplexRuleEngine
{
    public const FIELDS = [
        'from' => 'Nadawca (adres)',
        'from_domain' => 'Domena nadawcy',
        'from_name' => 'Nazwa nadawcy',
        'to' => 'Odbiorca (Do / DW)',
        'reply_to' => 'Reply-To',
        'return_path' => 'Return-Path (nadawca kopertowy)',
        'from_scope' => 'Nadawca wewnętrzny / zewnętrzny',
        'from_freemail' => 'Nadawca z darmowej poczty (gmail, wp, onet…)',
        'subject' => 'Temat',
        'body' => 'Treść',
        'header' => 'Nagłówek…',
        'attachment' => 'Nazwa załącznika',
        'attachment_type' => 'Typ MIME załącznika',
        'attachment_count' => 'Liczba załączników',
        'size_kb' => 'Rozmiar wiadomości (KB)',
        'message_type' => 'Typ wiadomości (autoodpowiedź, zwrot, lista…)',
        'sender_ip' => 'IP serwera nadawcy (Received)',
        'link_domain' => 'Domena linku w treści',
        'auth_spf' => 'Wynik SPF',
        'auth_dkim' => 'Wynik DKIM',
        'auth_dmarc' => 'Wynik DMARC',
        'mx_provider' => 'Poczta domeny nadawcy (MX: google, microsoft…)',
        'mx_host' => 'Serwer MX domeny nadawcy',
        'domain_age' => 'Wiek domeny nadawcy (dni, WHOIS/RDAP)',
    ];

    /**
     * Per field: type (text | number), whether it needs the body or a
     * network lookup (DNS MX, RDAP / WHOIS; SenderIntelService), and value
     * suggestions for the builders.
     */
    public const FIELD_META = [
        'body' => ['body' => true],
        'attachment' => ['body' => true],
        'attachment_type' => ['body' => true, 'suggest' => ['application/pdf', 'application/zip', 'application/x-msdownload', 'application/vnd.ms-excel', 'text/html', 'text/calendar']],
        'attachment_count' => ['body' => true, 'type' => 'number'],
        'size_kb' => ['type' => 'number'],
        // The trusted Received hop: the plugin cannot pick it, only the server.
        'sender_ip' => ['server' => true],
        'link_domain' => ['body' => true],
        'from_scope' => ['suggest' => ['internal', 'external']],
        'from_freemail' => ['suggest' => ['tak', 'nie']],
        'message_type' => ['suggest' => ['autoreply', 'bounce', 'list', 'calendar', 'signed', 'encrypted', 'readreceipt']],
        'auth_spf' => ['suggest' => ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']],
        'auth_dkim' => ['suggest' => ['pass', 'fail', 'none', 'neutral', 'policy', 'temperror', 'permerror']],
        'auth_dmarc' => ['suggest' => ['pass', 'fail', 'none', 'temperror', 'permerror']],
        'mx_provider' => ['network' => true, 'suggest' => SenderIntelService::PROVIDER_SLUGS],
        'mx_host' => ['network' => true],
        'domain_age' => ['network' => true, 'type' => 'number'],
    ];

    public const MATCHES = [
        'contains' => ['zawiera', 'nie zawiera'],
        'equals' => ['jest równe', 'nie jest równe'],
        'starts' => ['zaczyna się od', 'nie zaczyna się od'],
        'ends' => ['kończy się na', 'nie kończy się na'],
        'wildcard' => ['pasuje do wzorca (wildcard)', 'nie pasuje do wzorca (wildcard)'],
        'regex' => ['pasuje do regex', 'nie pasuje do regex'],
        'empty' => ['jest puste / brak', 'nie jest puste / istnieje'],
        'lt' => ['mniej niż', 'nie mniej niż'],
        'gt' => ['więcej niż', 'nie więcej niż'],
    ];

    /** Match types of numeric fields; text fields take the rest. */
    public const NUMBER_MATCHES = ['lt', 'gt', 'equals', 'empty'];

    public const ACTIONS = [
        'spam' => 'Spam (zawsze)',
        'quarantine' => 'Kwarantanna (co najmniej)',
        'score' => 'Dodaj punkty',
        'whitelist' => 'Biała lista (przepuść)',
        'log' => 'Tylko zapisz w dzienniku (test)',
    ];

    public const DEFAULT_SCORES = ['spam' => 10, 'quarantine' => 5, 'score' => 5, 'whitelist' => 0, 'log' => 0];

    public const MAX_DEPTH = 4;
    public const MAX_CONDITIONS = 30;
    public const MAX_VALUE = 500;
    public const MAX_NAME = 120;
    /** Body text taken into account (characters). */
    public const MAX_BODY = 262144;
    public const SCORE_MIN = -50;
    public const SCORE_MAX = 50;
    public const BACKTRACK_LIMIT = 100000;

    public static function isNumberField(string $field): bool
    {
        return (self::FIELD_META[$field]['type'] ?? 'text') === 'number';
    }

    public static function isNetworkField(string $field): bool
    {
        return !empty(self::FIELD_META[$field]['network']);
    }

    /**
     * Validate and canonicalize a condition tree (array or JSON string).
     * Unknown keys are dropped, values trimmed. Returns null with $errors set
     * when the tree is unusable.
     *
     * @param string[] $errors
     */
    public static function normalize($tree, ?array &$errors = null): ?array
    {
        $errors = [];
        if (is_string($tree)) {
            $tree = json_decode($tree, true);
        }
        if (!is_array($tree)) {
            $errors[] = 'Brak warunków reguły.';
            return null;
        }
        if (!isset($tree['op'])) {
            // A single condition: wrap it in an AND group.
            $tree = ['op' => 'and', 'items' => [$tree]];
        }
        $count = 0;
        $out = self::normalizeNode($tree, 1, $count, $errors);
        if ($count === 0 && !$errors) {
            $errors[] = 'Reguła musi mieć co najmniej jeden warunek.';
        }
        if ($count > self::MAX_CONDITIONS) {
            $errors[] = 'Za dużo warunków (maks. ' . self::MAX_CONDITIONS . ').';
        }
        return $errors ? null : $out;
    }

    private static function normalizeNode($node, int $depth, int &$count, array &$errors): ?array
    {
        if (!is_array($node)) {
            $errors[] = 'Nieprawidłowy warunek.';
            return null;
        }
        if (isset($node['op'])) {
            $op = strtolower((string)$node['op']);
            if ($op !== 'and' && $op !== 'or') {
                $errors[] = 'Grupa musi być typu „i” (and) albo „lub” (or).';
                return null;
            }
            if ($depth > self::MAX_DEPTH) {
                $errors[] = 'Za głębokie zagnieżdżenie grup (maks. ' . self::MAX_DEPTH . ' poziomy).';
                return null;
            }
            $items = [];
            foreach (is_array($node['items'] ?? null) ? $node['items'] : [] as $child) {
                $n = self::normalizeNode($child, $depth + 1, $count, $errors);
                if ($n !== null) {
                    $items[] = $n;
                }
            }
            if (!$items) {
                if (!$errors) {
                    $errors[] = 'Pusta grupa warunków - dodaj warunek albo usuń grupę.';
                }
                return null;
            }
            return ['op' => $op, 'items' => $items, 'negate' => !empty($node['negate'])];
        }

        $count++;
        $field = (string)($node['field'] ?? '');
        $match = (string)($node['match'] ?? 'contains');
        if (!isset(self::FIELDS[$field])) {
            $errors[] = 'Nieznane pole warunku: ' . $field;
            return null;
        }
        if (!isset(self::MATCHES[$match])) {
            $errors[] = 'Nieznany typ dopasowania: ' . $match;
            return null;
        }
        $number = self::isNumberField($field);
        $numeric = $match === 'lt' || $match === 'gt';
        if (($number && !in_array($match, self::NUMBER_MATCHES, true)) || (!$number && $numeric)) {
            $errors[] = $number
                ? 'Pole „' . self::FIELDS[$field] . '” porównuje liczby: wybierz „mniej niż”, „więcej niż”, „jest równe” albo „jest puste”.'
                : '„Mniej niż” / „więcej niż” działa tylko z polami liczbowymi (np. wiek domeny).';
            return null;
        }
        $out = ['field' => $field, 'match' => $match];
        if ($field === 'header') {
            $header = trim((string)($node['header'] ?? ''));
            if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9\-_.]{0,75}$/', $header)) {
                $errors[] = 'Podaj nazwę nagłówka (np. X-Mailer).';
                return null;
            }
            $out['header'] = $header;
        }
        $value = (string)($node['value'] ?? '');
        $value = $match === 'regex' ? trim($value) : self::fold($value);
        if ($number && $match !== 'empty') {
            if (!preg_match('/^-?\d{1,9}$/', $value)) {
                $errors[] = 'Pole „' . self::FIELDS[$field] . '” wymaga liczby całkowitej.';
                return null;
            }
            $value = (string)(int)$value;
        }
        if ($match !== 'empty') {
            if ($value === '') {
                $errors[] = 'Warunek „' . self::FIELDS[$field] . ' ' . self::MATCHES[$match][0] . '” wymaga wartości.';
                return null;
            }
            if (mb_strlen($value, 'UTF-8') > self::MAX_VALUE) {
                $errors[] = 'Wartość warunku jest za długa (maks. ' . self::MAX_VALUE . ' znaków).';
                return null;
            }
            if ($match === 'regex' && ($err = self::regexError($value))) {
                $errors[] = $err . ' (' . $value . ')';
                return null;
            }
            $out['value'] = $value;
        }
        $out['negate'] = !empty($node['negate']);
        return $out;
    }

    /** Lower-case, whitespace runs folded to one space, trimmed. */
    public static function fold($value): string
    {
        $value = mb_scrub((string)$value, 'UTF-8');
        $value = preg_replace('/\s+/u', ' ', $value) ?? $value;
        return trim(mb_strtolower($value, 'UTF-8'));
    }

    public static function regexError(string $pattern): string
    {
        $regex = self::regexOf($pattern);
        if (@preg_match($regex, '') === false) {
            return 'Nieprawidłowe wyrażenie regularne';
        }
        if (self::bounded($regex, str_repeat('a', 200) . '!') === false) {
            return 'Wyrażenie regularne jest zbyt kosztowne';
        }
        return '';
    }

    /**
     * Does the message match the tree?
     *
     * @param callable(string $field, ?string $header): string[] $values field values of the message
     */
    public static function evaluate(array $tree, callable $values): bool
    {
        if (isset($tree['op'])) {
            $and = $tree['op'] === 'and';
            $result = $and;
            foreach ($tree['items'] ?? [] as $item) {
                $hit = self::evaluate($item, $values);
                if ($and !== $hit) {
                    $result = $hit;
                    break;
                }
            }
            return empty($tree['negate']) ? $result : !$result;
        }
        $vals = $values((string)$tree['field'], $tree['header'] ?? null);
        $any = false;
        foreach ($vals as $v) {
            if (self::matchValue(self::fold($v), (string)$tree['match'], (string)($tree['value'] ?? ''))) {
                $any = true;
                break;
            }
        }
        if ($tree['match'] === 'empty' && !$vals) {
            $any = true;
        }
        return empty($tree['negate']) ? $any : !$any;
    }

    /** $value is already folded; $pattern as stored (folded, regex trimmed). */
    public static function matchValue(string $value, string $match, string $pattern): bool
    {
        switch ($match) {
            case 'lt':
                return is_numeric($value) && is_numeric($pattern) && (float)$value < (float)$pattern;
            case 'gt':
                return is_numeric($value) && is_numeric($pattern) && (float)$value > (float)$pattern;
            case 'empty':
                return $value === '';
            case 'contains':
                return $value !== '' && str_contains($value, $pattern);
            case 'equals':
                return $value === $pattern;
            case 'starts':
                return $value !== '' && str_starts_with($value, $pattern);
            case 'ends':
                return $value !== '' && str_ends_with($value, $pattern);
            case 'wildcard':
                return @preg_match('~^' . self::globToRegex($pattern) . '$~su', $value) === 1;
            case 'regex':
                return self::bounded(self::regexOf($pattern), $value) === 1;
        }
        return false;
    }

    /** Fields the tree reads (to fetch the body only when needed). */
    public static function fieldsUsed(array $tree): array
    {
        if (isset($tree['op'])) {
            $out = [];
            foreach ($tree['items'] ?? [] as $item) {
                $out = array_merge($out, self::fieldsUsed($item));
            }
            return array_values(array_unique($out));
        }
        return [(string)($tree['field'] ?? '')];
    }

    public static function needsBody(array $tree): bool
    {
        foreach (self::fieldsUsed($tree) as $f) {
            if (!empty(self::FIELD_META[$f]['body'])) {
                return true;
            }
        }
        return false;
    }

    /** Human-readable form: (Temat zawiera „faktura” I Treść nie zawiera „przelew”). */
    public static function describe(array $tree, bool $top = true): string
    {
        if (isset($tree['op'])) {
            $parts = array_map(fn ($i) => self::describe($i, false), $tree['items'] ?? []);
            $s = implode($tree['op'] === 'and' ? ' I ' : ' LUB ', $parts);
            if (!empty($tree['negate'])) {
                return 'NIE (' . $s . ')';
            }
            return $top || count($parts) < 2 ? $s : '(' . $s . ')';
        }
        $field = $tree['field'] === 'header' ? 'Nagłówek ' . ($tree['header'] ?? '') : (self::FIELDS[$tree['field']] ?? $tree['field']);
        $verb = self::MATCHES[$tree['match']][empty($tree['negate']) ? 0 : 1] ?? $tree['match'];
        return $field . ' ' . $verb . ($tree['match'] === 'empty' ? '' : ' „' . ($tree['value'] ?? '') . '”');
    }

    /** Field metadata for the builders: [{key, label, type, body, network, suggest}]. */
    public static function fieldList(): array
    {
        $out = [];
        foreach (self::FIELDS as $key => $label) {
            $m = self::FIELD_META[$key] ?? [];
            $out[] = ['key' => $key, 'label' => $label, 'type' => $m['type'] ?? 'text', 'body' => !empty($m['body']),
                'network' => !empty($m['network']), 'server' => !empty($m['network']) || !empty($m['server']), 'suggest' => $m['suggest'] ?? []];
        }
        return $out;
    }

    public static function clampScore($score, string $action): int
    {
        if ($action === 'whitelist' || $action === 'log') {
            return 0;
        }
        $score = (int)$score;
        if ($action === 'score') {
            return max(self::SCORE_MIN, min(self::SCORE_MAX, $score));
        }
        return max(0, min(self::SCORE_MAX, $score));
    }

    private static function regexOf(string $pattern): string
    {
        return '~' . str_replace('~', '\\~', $pattern) . '~iu';
    }

    /** @return int|false */
    private static function bounded(string $regex, string $value)
    {
        $previous = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', (string)self::BACKTRACK_LIMIT);
        try {
            $ok = @preg_match($regex, $value);
            return ($ok === false || preg_last_error() !== PREG_NO_ERROR) ? false : $ok;
        } finally {
            ini_set('pcre.backtrack_limit', (string)$previous);
        }
    }

    private static function globToRegex(string $glob): string
    {
        $out = '';
        foreach (preg_split('//u', $glob, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $c) {
            $out .= $c === '*' ? '.*' : ($c === '?' ? '.' : preg_quote($c, '~'));
        }
        return $out;
    }
}
