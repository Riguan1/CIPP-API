<?php
declare(strict_types=1);

namespace CbwPortal;

use RuntimeException;

/**
 * Client voor de CIPP-API.
 *
 * Haalt met de client credentials-flow een token bij Entra ID en roept daarmee
 * ListCbwReadiness aan. Dat endpoint geeft per controle een oordeel met het bewijs erbij, plus
 * een lijst NotDetectable: controles die Microsoft 365 niet kan bewijzen.
 *
 * Voorwaarden in CIPP: maak onder Settings > API access een API-client aan met de rol
 * Tenant.Reports.Read. Noteer de client id en het secret, en gebruik als scope
 * api://<client id van de CIPP-app>/.default.
 */
final class Cipp
{
    private ?string $token = null;
    private int $tokenVerlooptOp = 0;

    public function __construct(
        private string $baseUrl,
        private string $tenantId,
        private string $clientId,
        private string $clientSecret,
        private string $scope,
        private int $timeout = 60,
    ) {
        $this->baseUrl = rtrim($this->baseUrl, '/');
    }

    /**
     * Haalt de stand voor een tenant op.
     *
     * @return array{bevindingen: array<string, array>, nietTeMeten: array<string, string>, signalen: array<int, array>, opgehaald: string, tenant: string}
     */
    public function stand(string $tenant): array
    {
        $rapport = $this->get('/api/ListCbwReadiness?tenantFilter=' . rawurlencode($tenant));

        if (!isset($rapport['Controls']) || !is_array($rapport['Controls'])) {
            throw new RuntimeException(
                'CIPP gaf een antwoord zonder Controls terug. Draait ListCbwReadiness op deze CIPP-versie?'
            );
        }

        $bekend = Controls::plat();
        $bevindingen = [];
        $signalen = [];

        foreach ($rapport['Controls'] as $controle) {
            $id = (string)($controle['ControlId'] ?? '');
            $item = [
                'status' => (string)($controle['Status'] ?? 'onbekend'),
                'kop'    => (string)($controle['Headline'] ?? ''),
                'detail' => (string)($controle['Detail'] ?? ''),
                'bron'   => (string)($controle['Source'] ?? ''),
                'metric' => $controle['Metric'] ?? null,
            ];

            if ($id !== '' && isset($bekend[$id])) {
                $bevindingen[$id] = $item;
            } else {
                $signalen[] = $item + ['artikel' => (string)($controle['Article'] ?? '')];
            }
        }

        $nietTeMeten = [];
        foreach ($rapport['NotDetectable'] ?? [] as $rij) {
            $id = (string)($rij['ControlId'] ?? '');
            if ($id !== '') {
                $nietTeMeten[$id] = (string)($rij['Reason'] ?? '');
            }
        }

        return [
            'bevindingen' => $bevindingen,
            'nietTeMeten' => $nietTeMeten,
            'signalen'    => $signalen,
            'opgehaald'   => (string)($rapport['GeneratedAt'] ?? gmdate('c')),
            'tenant'      => (string)($rapport['TenantFilter'] ?? $tenant),
        ];
    }

    public function test(string $tenant): array
    {
        try {
            $stand = $this->stand($tenant);
            $bruikbaar = count(array_filter(
                $stand['bevindingen'],
                static fn(array $b) => $b['status'] !== 'onbekend',
            ));
            return ['ok' => true, 'bericht' => sprintf(
                '%d bevindingen ontvangen voor %s, waarvan %d bruikbaar.',
                count($stand['bevindingen']), $stand['tenant'], $bruikbaar,
            )];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'bericht' => $e->getMessage()];
        }
    }

    private function token(): string
    {
        if ($this->token !== null && time() < $this->tokenVerlooptOp - 60) {
            return $this->token;
        }

        $url = "https://login.microsoftonline.com/{$this->tenantId}/oauth2/v2.0/token";
        $body = http_build_query([
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'scope'         => $this->scope,
            'grant_type'    => 'client_credentials',
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
        ]);
        $ruw = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $fout = curl_error($ch);
        curl_close($ch);

        if ($ruw === false) {
            throw new RuntimeException("Entra ID niet bereikbaar: {$fout}");
        }

        $antwoord = json_decode((string)$ruw, true);
        if (!is_array($antwoord) || !isset($antwoord['access_token'])) {
            $omschrijving = is_array($antwoord)
                ? (string)($antwoord['error_description'] ?? $antwoord['error'] ?? 'onbekende fout')
                : 'geen leesbaar antwoord';
            throw new RuntimeException("Geen token van Entra ID (HTTP {$httpcode}): {$omschrijving}");
        }

        $this->token = (string)$antwoord['access_token'];
        $this->tokenVerlooptOp = time() + (int)($antwoord['expires_in'] ?? 3600);

        return $this->token;
    }

    /** @return array<string, mixed> */
    private function get(string $pad): array
    {
        $ch = curl_init($this->baseUrl . $pad);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => [
                'Authorization: Bearer ' . $this->token(),
                'Accept: application/json',
            ],
        ]);
        $ruw = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $fout = curl_error($ch);
        curl_close($ch);

        if ($ruw === false) {
            throw new RuntimeException("CIPP niet bereikbaar: {$fout}");
        }

        $antwoord = json_decode((string)$ruw, true);

        if ($httpcode === 401 || $httpcode === 403) {
            throw new RuntimeException(
                "CIPP weigert de toegang (HTTP {$httpcode}). Controleer of de API-client bestaat, is " .
                'ingeschakeld en de rol Tenant.Reports.Read heeft, en of het IP van deze server is toegestaan.'
            );
        }
        if ($httpcode !== 200) {
            $bericht = is_array($antwoord) ? (string)($antwoord['Error'] ?? '') : '';
            throw new RuntimeException("CIPP antwoordde met HTTP {$httpcode}. {$bericht}");
        }
        if (!is_array($antwoord)) {
            throw new RuntimeException('CIPP gaf geen leesbare JSON terug.');
        }

        return $antwoord;
    }
}
