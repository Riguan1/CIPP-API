<?php
declare(strict_types=1);

namespace CbwPortal;

use RuntimeException;

/**
 * Client voor de HostBill Admin API.
 *
 * De API zit op /admin/api.php en neemt api_id, api_key en call als parameters; het antwoord is
 * JSON met een success-vlag, en bij een fout een error-array. De API-sleutel is per methode
 * geautoriseerd in HostBill onder Settings > Security > API access: geef hem alleen de calls die
 * hieronder worden gebruikt, niets meer.
 *
 * Gebruikte calls: getClients, getClientDetails, getClientTickets.
 */
final class HostBill
{
    public function __construct(
        private string $baseUrl,
        private string $apiId,
        private string $apiKey,
        private int $timeout = 20,
    ) {
        $this->baseUrl = rtrim($this->baseUrl, '/');
    }

    /**
     * @return array<int, array{id: string, naam: string, bedrijf: string, email: string, status: string}>
     */
    public function klanten(): array
    {
        $antwoord = $this->call('getClients', ['perpage' => 500]);
        $rijen = $antwoord['clients'] ?? [];

        $klanten = [];
        foreach ($rijen as $rij) {
            $id = (string)($rij['id'] ?? '');
            if ($id === '') {
                continue;
            }
            $klanten[] = [
                'id'      => $id,
                'naam'    => trim((string)($rij['firstname'] ?? '') . ' ' . (string)($rij['lastname'] ?? '')),
                'bedrijf' => (string)($rij['companyname'] ?? ''),
                'email'   => (string)($rij['email'] ?? ''),
                'status'  => (string)($rij['status'] ?? ''),
            ];
        }

        usort($klanten, static fn(array $a, array $b) => strcasecmp(
            $a['bedrijf'] !== '' ? $a['bedrijf'] : $a['naam'],
            $b['bedrijf'] !== '' ? $b['bedrijf'] : $b['naam'],
        ));

        return $klanten;
    }

    /** @return array<string, mixed> */
    public function klant(string $clientId): array
    {
        $antwoord = $this->call('getClientDetails', ['id' => $clientId]);
        $klant = $antwoord['client'] ?? [];

        if ($klant === []) {
            throw new RuntimeException("HostBill kent geen klant met id {$clientId}.");
        }

        return $klant;
    }

    /**
     * Zoekt de tenantnaam in de custom fields van de klant. HostBill levert custom fields in
     * verschillende vormen aan, afhankelijk van versie en configuratie, dus we accepteren ze allemaal
     * en geven null terug als we niets herkennen - liever geen koppeling dan de verkeerde tenant.
     */
    public function tenantUitKlant(array $klant, string $veldnaam): ?string
    {
        $velden = $klant['custom_fields'] ?? $klant['customfields'] ?? [];
        if (!is_array($velden)) {
            return null;
        }

        foreach ($velden as $sleutel => $veld) {
            // vorm 1: ['Tenant' => 'klant.onmicrosoft.com']
            if (is_string($sleutel) && is_string($veld) && strcasecmp($sleutel, $veldnaam) === 0) {
                return $this->schoon($veld);
            }
            // vorm 2: [['name' => 'Tenant', 'value' => '...'], ...]
            if (is_array($veld)) {
                $naam = (string)($veld['name'] ?? $veld['fieldname'] ?? '');
                if ($naam !== '' && strcasecmp($naam, $veldnaam) === 0) {
                    return $this->schoon((string)($veld['value'] ?? ''));
                }
            }
        }

        return null;
    }

    /**
     * Levert een bevinding voor controle b3: worden incidenten met een tijdstip vastgelegd?
     *
     * HostBill is bij de meeste partijen feitelijk het incidentregister. Wat het systeem kan
     * aantonen is dat er een registratie met tijdstempels bestaat - niet welke daarvan een
     * beveiligingsincident was. Daarom nooit meer dan 'deels': voor de meldplicht moet herleidbaar
     * zijn wanneer een incident is ontdekt, en dat vraagt een herkenbaar label of een eigen afdeling.
     *
     * @return array<string, array{status: string, kop: string, detail: string, bron: string}>
     */
    public function incidentregistratie(string $clientId): array
    {
        // Een storing gooit door naar Meting, die er een waarschuwing van maakt en de vorige stand
        // laat staan. Hier stilzwijgend 'onbekend' teruggeven zou de bestaande bevinding wissen.
        $antwoord = $this->call('getClientTickets', ['id' => $clientId]);

        $tickets = $antwoord['tickets'] ?? [];
        $grens = time() - (365 * 86400);
        $recent = 0;

        foreach ($tickets as $ticket) {
            foreach (['date_created', 'datecreated', 'date', 'created_at'] as $sleutel) {
                $waarde = $ticket[$sleutel] ?? null;
                $tijd = is_numeric($waarde) ? (int)$waarde : (is_string($waarde) ? strtotime($waarde) : false);
                if ($tijd !== false && $tijd !== 0 && $tijd >= $grens) {
                    $recent++;
                    break;
                }
            }
        }

        if ($recent === 0) {
            return ['b3' => [
                'status' => 'onbekend',
                'kop'    => 'Geen tickets van het afgelopen jaar gevonden',
                'detail' => 'Dat betekent niet dat er geen incidentregistratie is - het betekent dat wij hier geen '
                          . 'registratie zien. Leg vast waar incidenten worden bijgehouden.',
                'bron'   => 'HostBill - tickets',
            ]];
        }

        return ['b3' => [
            'status' => 'deels',
            'kop'    => "{$recent} tickets met tijdstempel in het afgelopen jaar",
            'detail' => 'Er is een registratie met tijdstippen. Voor de meldplicht moet daarnaast herleidbaar zijn '
                      . 'welke meldingen beveiligingsincidenten waren en wanneer ze zijn ontdekt - geef die een eigen '
                      . 'afdeling of label, want dat tijdstip start de 24-uursklok.',
            'bron'   => 'HostBill - tickets',
        ]];
    }

    /** Test de verbinding en geeft een leesbare uitkomst terug voor de diagnosepagina. */
    public function test(): array
    {
        try {
            $klanten = $this->klanten();
            return ['ok' => true, 'bericht' => count($klanten) . ' klanten opgehaald uit HostBill.'];
        } catch (RuntimeException $e) {
            return ['ok' => false, 'bericht' => $e->getMessage()];
        }
    }

    /** @return array<string, mixed> */
    private function call(string $methode, array $parameters = []): array
    {
        $body = http_build_query($parameters + [
            'api_id' => $this->apiId,
            'api_key' => $this->apiKey,
            'call'    => $methode,
        ]);

        $ch = curl_init($this->baseUrl . '/admin/api.php');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $ruw = curl_exec($ch);
        $fout = curl_error($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($ruw === false) {
            throw new RuntimeException("HostBill niet bereikbaar: {$fout}");
        }
        if ($httpcode !== 200) {
            throw new RuntimeException("HostBill antwoordde met HTTP {$httpcode} op {$methode}.");
        }

        $antwoord = json_decode((string)$ruw, true);
        if (!is_array($antwoord)) {
            throw new RuntimeException(
                "HostBill gaf geen leesbare JSON terug op {$methode}. Controleer of de basis-URL naar de " .
                'HostBill-installatie wijst en niet naar een inlogpagina of proxy.'
            );
        }

        if (($antwoord['success'] ?? false) !== true) {
            $fouten = $antwoord['error'] ?? $antwoord['errors'] ?? ['onbekende fout'];
            $tekst = is_array($fouten) ? implode('; ', array_map('strval', $fouten)) : (string)$fouten;
            throw new RuntimeException(
                "HostBill weigerde {$methode}: {$tekst}. Controleer of deze call is aangevinkt bij de " .
                'API-sleutel onder Settings > Security > API access.'
            );
        }

        return $antwoord;
    }

    private function schoon(string $waarde): ?string
    {
        $waarde = trim($waarde);
        return $waarde === '' ? null : $waarde;
    }
}
