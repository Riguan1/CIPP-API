<?php
declare(strict_types=1);

namespace CbwPortal;

use Throwable;

/**
 * Haalt de stand van één klant op uit alle gekoppelde bronnen.
 *
 * Drie bronnen, los van elkaar opgehaald: CIPP voor de tenant, de back-upbron voor de kopie buiten
 * de tenant, en HostBill voor de incidentregistratie.
 *
 * Twee regels die hier het werk doen:
 *
 * 1. Bronnen vullen elkaar aan, ze vervangen elkaar niet. De nieuwe meting wordt over de vorige
 *    stand heen gelegd. Valt CIPP uit terwijl de back-up wel antwoordt, dan blijven de
 *    CIPP-bevindingen van gisteren staan in plaats van te verdwijnen - met hun eigen meetmoment,
 *    zodat niemand oude gegevens voor vers aanziet.
 * 2. Een bron die niet antwoordt levert een waarschuwing, geen stand. Alleen als élke bron faalt
 *    én er nog niets was, blijft de stand leeg.
 *
 * Dit is de enige plek waar bronnen worden samengevoegd, zodat de nachtelijke run en de knop in
 * het beheerscherm niet uit elkaar kunnen lopen.
 */
final class Meting
{
    public function __construct(private Config $config)
    {
    }

    /**
     * @param array  $klant  Rij uit de klanttabel.
     * @param ?array $vorige De laatst bewaarde stand, als die er is.
     * @return array{stand: ?array, waarschuwingen: array<int, string>, gemeten: int}
     */
    public function voorKlant(array $klant, ?array $vorige = null): array
    {
        $tenant = (string)($klant['tenant'] ?? '');
        $stand = $vorige;
        $waarschuwingen = [];
        $nieuw = 0;

        if ($tenant === '') {
            $waarschuwingen[] = 'CIPP: geen tenant gekoppeld aan deze klant.';
        } else {
            try {
                $cipp = $this->config->cipp()->stand($tenant);
                $stand = $this->voegToe($stand, $tenant, $cipp['bevindingen']);
                $stand['signalen'] = $cipp['signalen'];
                $stand['tenant'] = $cipp['tenant'];
                foreach ($cipp['nietTeMeten'] as $id => $reden) {
                    // Alleen melden dat iets niet te meten is als geen andere bron het wél weet.
                    if (($stand['bevindingen'][$id]['status'] ?? 'onbekend') === 'onbekend') {
                        $stand['nietTeMeten'][$id] = $reden;
                    }
                }
                $nieuw += count($cipp['bevindingen']);
            } catch (Throwable $e) {
                $waarschuwingen[] = 'CIPP: ' . $e->getMessage();
            }
        }

        $backupRef = (string)($klant['backup_ref'] ?? '');
        if ($backupRef !== '') {
            try {
                $bron = $this->config->backupBron();
                if ($bron !== null) {
                    $bevindingen = $bron->bevindingen($backupRef);
                    $stand = $this->voegToe($stand, $tenant, $bevindingen);
                    $nieuw += count($bevindingen);
                }
            } catch (Throwable $e) {
                $waarschuwingen[] = 'Back-up: ' . $e->getMessage();
            }
        }

        try {
            $tickets = $this->config->hostbill()->incidentregistratie((string)$klant['client_id']);
            $stand = $this->voegToe($stand, $tenant, $tickets);
            $nieuw += count($tickets);
        } catch (Throwable $e) {
            $waarschuwingen[] = 'HostBill: ' . $e->getMessage();
        }

        if ($stand !== null && $nieuw > 0) {
            $stand['opgehaald'] = gmdate('c');
        }

        return ['stand' => $stand, 'waarschuwingen' => $waarschuwingen, 'gemeten' => $nieuw];
    }

    /**
     * Legt bevindingen over de bestaande stand heen, elk met het moment waarop ze zijn gemeten.
     * Een echte meting vervangt de melding dat iets niet te meten was; een bevinding 'onbekend'
     * laat die melding staan, want dan weten we nog steeds niets.
     *
     * @param array<string, array> $bevindingen
     */
    private function voegToe(?array $stand, string $tenant, array $bevindingen): array
    {
        $stand ??= [
            'bevindingen' => [],
            'nietTeMeten' => [],
            'signalen'    => [],
            'opgehaald'   => gmdate('c'),
            'tenant'      => $tenant,
        ];

        $stand['bevindingen'] ??= [];
        $stand['nietTeMeten'] ??= [];
        $stand['signalen'] ??= [];

        foreach ($bevindingen as $id => $bevinding) {
            $bevinding['gemeten'] = gmdate('c');
            $stand['bevindingen'][$id] = $bevinding;

            if (($bevinding['status'] ?? 'onbekend') !== 'onbekend') {
                unset($stand['nietTeMeten'][$id]);
            }
        }

        return $stand;
    }
}
