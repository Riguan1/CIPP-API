<?php
declare(strict_types=1);

namespace CbwPortal\Backup;

use RuntimeException;

/**
 * NinjaOne als back-upbron.
 *
 * Authenticatie: OAuth 2.0 client credentials tegen /ws/oauth/token met scope 'monitoring'
 * (alleen lezen). Maak de client aan in NinjaOne onder Administration > Apps > API, type
 * "Machine to Machine".
 *
 * Gebruikte endpoints:
 *   GET /v2/organizations                    om klanten te koppelen
 *   GET /v2/backup/jobs                      back-uptaken en hun resultaat
 *   GET /v2/backup/integrity-check-jobs      verificatie van herstelbaarheid
 *
 * De basis-URL verschilt per regio: app.ninjarmm.com, eu.ninjarmm.com, oc.ninjarmm.com. Vul de
 * URL van uw eigen instantie in.
 */
final class NinjaOne implements Bron
{
    private ?string $token = null;
    private int $tokenVerlooptOp = 0;

    public function __construct(
        private string $baseUrl,
        private string $clientId,
        private string $clientSecret,
        private int $verseDagen = 2,
        private int $timeout = 30,
    ) {
        $this->baseUrl = rtrim($this->baseUrl, '/');
    }

    public function naam(): string
    {
        return 'NinjaOne';
    }

    public function organisaties(): array
    {
        $uit = [];
        foreach ($this->get('/v2/organizations') as $org) {
            $id = (string)($org['id'] ?? '');
            if ($id !== '') {
                $uit[] = ['id' => $id, 'naam' => (string)($org['name'] ?? $id)];
            }
        }
        return $uit;
    }

    public function bevindingen(string $referentie): array
    {
        $taken = $this->takenVoor($referentie, '/v2/backup/jobs');
        $checks = $this->takenVoor($referentie, '/v2/backup/integrity-check-jobs');

        return [
            'c1' => $this->backupOordeel($taken),
            'c2' => $this->herstelOordeel($checks),
        ];
    }

    /** @param array<int, array> $taken */
    private function backupOordeel(array $taken): array
    {
        if ($taken === []) {
            return [
                'status' => 'onbekend',
                'kop'    => 'Geen back-uptaken gevonden voor deze organisatie in NinjaOne',
                'detail' => 'Dat betekent niet dat er geen back-up is - het betekent dat wij hem hier niet zien. '
                          . 'Controleer de koppeling, of leg de back-up handmatig vast.',
                'bron'   => 'NinjaOne - back-uptaken',
            ];
        }

        $grens = time() - ($this->verseDagen * 86400);
        $recent = array_filter($taken, fn(array $t) => $this->tijd($t) >= $grens);
        $geslaagd = array_filter($recent, fn(array $t) => $this->geslaagd($t));

        $totaal = count($taken);
        $aantalRecent = count($recent);
        $aantalGoed = count($geslaagd);

        if ($aantalRecent === 0) {
            return [
                'status' => 'open',
                'kop'    => "Laatste back-up is ouder dan {$this->verseDagen} dagen ({$totaal} taken bekend)",
                'detail' => 'Een back-up die stilstaat, beschermt alleen wat er al stond.',
                'bron'   => 'NinjaOne - back-uptaken',
            ];
        }

        $percentage = (int)round(($aantalGoed / $aantalRecent) * 100);
        $status = $percentage >= 95 ? 'geregeld' : ($percentage >= 60 ? 'deels' : 'open');

        return [
            'status' => $status,
            'kop'    => "{$aantalGoed} van {$aantalRecent} recente back-uptaken geslaagd ({$percentage}%)",
            'detail' => "Gemeten over de laatste {$this->verseDagen} dagen. Controleer dat de reikwijdte van de "
                      . 'taken ook echt alle kritieke data dekt; het aantal geslaagde taken zegt niets over wat erin zit.',
            'bron'   => 'NinjaOne - back-uptaken',
        ];
    }

    /** @param array<int, array> $checks */
    private function herstelOordeel(array $checks): array
    {
        if ($checks === []) {
            return [
                'status' => 'onbekend',
                'kop'    => 'Geen integriteitscontroles gevonden in NinjaOne',
                'detail' => 'De zorgplicht vraagt om een aantoonbaar geslaagde herstelproef. Leg die met datum en '
                          . 'uitkomst vast, of zet integriteitscontroles aan.',
                'bron'   => 'NinjaOne - integriteitscontroles',
            ];
        }

        $laatste = 0;
        $goed = 0;
        foreach ($checks as $check) {
            $laatste = max($laatste, $this->tijd($check));
            if ($this->geslaagd($check)) {
                $goed++;
            }
        }

        $ouderdom = $laatste > 0 ? (int)floor((time() - $laatste) / 86400) : null;
        $wanneer = $ouderdom === null ? 'onbekend wanneer' : "laatste {$ouderdom} dagen geleden";

        // Bewust 'deels' en niet 'geregeld': een geautomatiseerde integriteitscontrole toont dat de
        // back-up leesbaar is, niet dat de organisatie een herstelproef heeft gedaan en beschreven.
        return [
            'status' => $goed > 0 ? 'deels' : 'open',
            'kop'    => "{$goed} van " . count($checks) . " integriteitscontroles geslaagd ({$wanneer})",
            'detail' => 'Dit toont dat de back-up leesbaar is. Voor de zorgplicht telt daarnaast een beschreven '
                      . 'herstelproef: wat is teruggezet, hoe lang duurde het, en wat bleek er niet te kloppen.',
            'bron'   => 'NinjaOne - integriteitscontroles',
        ];
    }

    public function test(): array
    {
        try {
            $organisaties = $this->organisaties();
            return ['ok' => true, 'bericht' => count($organisaties) . ' organisaties gevonden in NinjaOne.'];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'bericht' => $e->getMessage()];
        }
    }

    /** @return array<int, array> */
    private function takenVoor(string $referentie, string $pad): array
    {
        try {
            $rijen = $this->get($pad);
        } catch (RuntimeException $e) {
            // Een organisatie zonder back-upmodule geeft geen taken; dat is geen storing.
            if (str_contains($e->getMessage(), '404')) {
                return [];
            }
            throw $e;
        }

        return array_values(array_filter($rijen, static function (array $rij) use ($referentie): bool {
            foreach (['organizationId', 'organisationId', 'clientId'] as $sleutel) {
                if (isset($rij[$sleutel]) && (string)$rij[$sleutel] === $referentie) {
                    return true;
                }
            }
            return false;
        }));
    }

    private function tijd(array $rij): int
    {
        foreach (['endTime', 'createTime', 'startTime', 'timestamp'] as $sleutel) {
            $waarde = $rij[$sleutel] ?? null;
            if (is_numeric($waarde)) {
                // NinjaOne levert epoch-seconden, soms met decimalen.
                return (int)$waarde;
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

    private function geslaagd(array $rij): bool
    {
        $status = strtoupper((string)($rij['status'] ?? $rij['result'] ?? $rij['jobStatus'] ?? ''));
        return in_array($status, ['SUCCEEDED', 'SUCCESS', 'COMPLETED', 'OK', 'PASSED'], true);
    }

    /** @return array<int, array> */
    private function get(string $pad): array
    {
        $ch = curl_init($this->baseUrl . $pad);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $this->token(), 'Accept: application/json'],
        ]);
        $ruw = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $fout = curl_error($ch);
        curl_close($ch);

        if ($ruw === false) {
            throw new RuntimeException("NinjaOne niet bereikbaar: {$fout}");
        }
        if ($httpcode === 401 || $httpcode === 403) {
            throw new RuntimeException(
                "NinjaOne weigert de toegang (HTTP {$httpcode}). Heeft de API-client de scope 'monitoring'?"
            );
        }
        if ($httpcode !== 200) {
            throw new RuntimeException("NinjaOne antwoordde met HTTP {$httpcode} op {$pad}.");
        }

        $antwoord = json_decode((string)$ruw, true);
        if (!is_array($antwoord)) {
            throw new RuntimeException("NinjaOne gaf geen leesbare JSON terug op {$pad}.");
        }

        // Sommige endpoints verpakken de lijst, andere geven hem los.
        foreach (['results', 'data', 'jobs'] as $sleutel) {
            if (isset($antwoord[$sleutel]) && is_array($antwoord[$sleutel])) {
                return $antwoord[$sleutel];
            }
        }

        return array_is_list($antwoord) ? $antwoord : [$antwoord];
    }

    private function token(): string
    {
        if ($this->token !== null && time() < $this->tokenVerlooptOp - 60) {
            return $this->token;
        }

        $ch = curl_init($this->baseUrl . '/ws/oauth/token');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'grant_type'    => 'client_credentials',
                'client_id'     => $this->clientId,
                'client_secret' => $this->clientSecret,
                'scope'         => 'monitoring',
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
        ]);
        $ruw = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $antwoord = is_string($ruw) ? json_decode($ruw, true) : null;
        if (!is_array($antwoord) || !isset($antwoord['access_token'])) {
            $reden = is_array($antwoord) ? (string)($antwoord['error_description'] ?? $antwoord['error'] ?? '') : '';
            throw new RuntimeException("Geen token van NinjaOne (HTTP {$httpcode}). {$reden}");
        }

        $this->token = (string)$antwoord['access_token'];
        $this->tokenVerlooptOp = time() + (int)($antwoord['expires_in'] ?? 3600);

        return $this->token;
    }
}
