<?php
declare(strict_types=1);

namespace CbwPortal\Backup;

use RuntimeException;

/**
 * Datto SaaS Protection als back-upbron.
 *
 * Authenticatie: HTTP Basic met de publieke en geheime sleutel uit het Datto Partner Portal
 * (Admin > Integrations > Create API Key).
 *
 * Gebruikte endpoints:
 *   GET /v1/saas/domains                  de beschermde organisaties, met hun saasCustomerId
 *   GET /v1/saas/{saasCustomerId}/seats   per seat de back-upstatus en het laatste moment
 *
 * Datto beschermt hier de Microsoft 365-data zelf, buiten de tenant. Dat is precies wat controle
 * c1 vraagt. Voor c2 geldt de eerlijke beperking: seat-status bewijst dat er een back-up ligt,
 * niet dat er ooit iets uit is teruggezet.
 */
final class DattoSaaS implements Bron
{
    public function __construct(
        private string $baseUrl,
        private string $publicKey,
        private string $secretKey,
        private int $verseDagen = 2,
        private int $timeout = 30,
    ) {
        $this->baseUrl = rtrim($this->baseUrl, '/');
    }

    public function naam(): string
    {
        return 'Datto SaaS Protection';
    }

    public function organisaties(): array
    {
        $uit = [];
        foreach ($this->get('/v1/saas/domains') as $domein) {
            $id = (string)($domein['saasCustomerId'] ?? $domein['id'] ?? '');
            if ($id !== '') {
                $uit[] = [
                    'id'   => $id,
                    'naam' => (string)($domein['domain'] ?? $domein['name'] ?? $id),
                ];
            }
        }
        return $uit;
    }

    public function bevindingen(string $referentie): array
    {
        $seats = $this->get('/v1/saas/' . rawurlencode($referentie) . '/seats');

        if ($seats === []) {
            return [
                'c1' => [
                    'status' => 'onbekend',
                    'kop'    => 'Geen beschermde seats gevonden bij Datto voor deze organisatie',
                    'detail' => 'Dat betekent niet dat er geen back-up is - het betekent dat wij hem hier niet zien. '
                              . 'Controleer de koppeling, of leg de back-up handmatig vast.',
                    'bron'   => 'Datto SaaS Protection - seats',
                ],
                'c2' => $this->herstelOordeel(),
            ];
        }

        $actief = array_values(array_filter($seats, static function (array $seat): bool {
            $status = strtolower((string)($seat['seatState'] ?? $seat['status'] ?? ''));
            return !in_array($status, ['paused', 'archived', 'unprotected', 'inactive'], true);
        }));

        $grens = time() - ($this->verseDagen * 86400);
        $vers = array_filter($actief, fn(array $s) => $this->laatsteBackup($s) >= $grens);

        $totaal = count($seats);
        $aantalActief = count($actief);
        $aantalVers = count($vers);

        if ($aantalActief === 0) {
            return [
                'c1' => [
                    'status' => 'open',
                    'kop'    => "Alle {$totaal} seats bij Datto staan gepauzeerd of gearchiveerd",
                    'detail' => 'Er loopt geen actieve bescherming van de Microsoft 365-data.',
                    'bron'   => 'Datto SaaS Protection - seats',
                ],
                'c2' => $this->herstelOordeel(),
            ];
        }

        $percentage = (int)round(($aantalVers / $aantalActief) * 100);
        $status = $percentage >= 95 ? 'geregeld' : ($percentage >= 60 ? 'deels' : 'open');

        return [
            'c1' => [
                'status' => $status,
                'kop'    => "{$aantalVers} van {$aantalActief} beschermde seats ({$percentage}%) is de laatste "
                          . "{$this->verseDagen} dagen geback-upt",
                'detail' => $aantalActief < $totaal
                    ? ($totaal - $aantalActief) . ' van de ' . $totaal . ' seats staat gepauzeerd of gearchiveerd; '
                      . 'controleer of dat klopt met wie er in dienst is.'
                    : 'Alle seats staan actief beschermd.',
                'bron'   => 'Datto SaaS Protection - seats',
            ],
            'c2' => $this->herstelOordeel(),
        ];
    }

    /**
     * Datto toont dat er een back-up ligt, niet dat er een herstelproef is gedaan. Die twee door
     * elkaar halen is precies de fout die een organisatie bij het eerste echte incident ontdekt.
     */
    private function herstelOordeel(): array
    {
        return [
            'status' => 'onbekend',
            'kop'    => 'Een herstelproef is niet uit Datto af te leiden',
            'detail' => 'De back-upstatus bewijst dat er data ligt, niet dat een terugzetactie is uitgevoerd en '
                      . 'geslaagd. Voer minimaal jaarlijks een herstelproef uit en leg datum, omvang en uitkomst vast.',
            'bron'   => 'Datto SaaS Protection',
        ];
    }

    private function laatsteBackup(array $seat): int
    {
        foreach (['lastBackupDate', 'lastBackup', 'lastBackupTime', 'lastSuccessfulBackup'] as $sleutel) {
            $waarde = $seat[$sleutel] ?? null;
            if (is_numeric($waarde)) {
                // Datto levert soms milliseconden.
                $getal = (int)$waarde;
                return $getal > 100000000000 ? intdiv($getal, 1000) : $getal;
            }
            if (is_string($waarde) && $waarde !== '') {
                $tijd = strtotime($waarde);
                if ($tijd !== false) {
                    return $tijd;
                }
            }
        }
        return 0;
    }

    public function test(): array
    {
        try {
            $organisaties = $this->organisaties();
            return ['ok' => true, 'bericht' => count($organisaties) . ' beschermde organisaties gevonden bij Datto.'];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'bericht' => $e->getMessage()];
        }
    }

    /** @return array<int, array> */
    private function get(string $pad): array
    {
        $ch = curl_init($this->baseUrl . $pad);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_USERPWD        => $this->publicKey . ':' . $this->secretKey,
            CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $ruw = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $fout = curl_error($ch);
        curl_close($ch);

        if ($ruw === false) {
            throw new RuntimeException("Datto niet bereikbaar: {$fout}");
        }
        if ($httpcode === 401 || $httpcode === 403) {
            throw new RuntimeException(
                "Datto weigert de toegang (HTTP {$httpcode}). Controleer de API-sleutels uit het Partner Portal."
            );
        }
        if ($httpcode === 404) {
            throw new RuntimeException("Datto kent {$pad} niet (HTTP 404). Klopt de saasCustomerId?");
        }
        if ($httpcode !== 200) {
            throw new RuntimeException("Datto antwoordde met HTTP {$httpcode} op {$pad}.");
        }

        $antwoord = json_decode((string)$ruw, true);
        if (!is_array($antwoord)) {
            throw new RuntimeException("Datto gaf geen leesbare JSON terug op {$pad}.");
        }

        foreach (['items', 'seats', 'domains', 'data', 'results'] as $sleutel) {
            if (isset($antwoord[$sleutel]) && is_array($antwoord[$sleutel])) {
                return $antwoord[$sleutel];
            }
        }

        return array_is_list($antwoord) ? $antwoord : [$antwoord];
    }
}
