<?php
declare(strict_types=1);

/**
 * Nachtelijke meting: haalt voor elke gekoppelde klant de stand op uit CIPP en bewaart die.
 *
 *   php bin/sync.php            alle klanten met een tenant
 *   php bin/sync.php 42         alleen HostBill-klant 42
 *
 * Cron, elke nacht om 03:20:
 *   20 3 * * * php /pad/naar/CbwPortal/bin/sync.php >> /var/log/cbw-sync.log 2>&1
 *
 * Een mislukte meting laat de vorige stand staan en noteert de fout. De klant ziet dan de datum
 * van de laatste geslaagde meting, niet een leeg of misleidend scherm.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;

$config = Config::laden();
$dossier = $config->dossier();
$cipp = $config->cipp();
$backup = $config->backupBron();

if ($backup === null) {
    echo "let op: geen back-upbron ingesteld, c1 en c2 blijven handwerk\n\n";
}

$alleen = $argv[1] ?? null;
$gelukt = 0;
$mislukt = 0;

foreach ($dossier->klanten() as $klant) {
    $clientId = (string)$klant['client_id'];
    $tenant = (string)($klant['tenant'] ?? '');

    if ($alleen !== null && $clientId !== $alleen) {
        continue;
    }
    if ($tenant === '') {
        printf("overgeslagen  %-24s geen tenant gekoppeld\n", $klant['naam']);
        continue;
    }

    // De twee bronnen worden los opgehaald: valt CIPP uit, dan is de back-upstand nog steeds bruikbaar.
    $stand = null;
    $waarschuwingen = [];

    try {
        $stand = $cipp->stand($tenant);
    } catch (Throwable $e) {
        $waarschuwingen[] = 'CIPP: ' . $e->getMessage();
    }

    $backupRef = (string)($klant['backup_ref'] ?? '');
    if ($backup !== null && $backupRef !== '') {
        try {
            $bevindingen = $backup->bevindingen($backupRef);
            $stand ??= ['bevindingen' => [], 'nietTeMeten' => [], 'signalen' => [], 'opgehaald' => gmdate('c'), 'tenant' => $tenant];
            foreach ($bevindingen as $id => $bevinding) {
                $stand['bevindingen'][$id] = $bevinding;
                // Een echte meting vervangt de melding dat iets niet te meten was.
                if ($bevinding['status'] !== 'onbekend') {
                    unset($stand['nietTeMeten'][$id]);
                }
            }
        } catch (Throwable $e) {
            $waarschuwingen[] = $backup->naam() . ': ' . $e->getMessage();
        }
    }

    if ($stand === null) {
        $dossier->standOpslaan($clientId, null, implode(' | ', $waarschuwingen));
        printf("MISLUKT       %-24s %s\n", $klant['naam'], implode(' | ', $waarschuwingen));
        $mislukt++;
    } else {
        $dossier->standOpslaan($clientId, $stand, $waarschuwingen === [] ? null : implode(' | ', $waarschuwingen));
        $bruikbaar = count(array_filter($stand['bevindingen'], static fn($b) => $b['status'] !== 'onbekend'));
        printf(
            "gemeten       %-24s %d bevindingen, %d bruikbaar%s\n",
            $klant['naam'], count($stand['bevindingen']), $bruikbaar,
            $waarschuwingen === [] ? '' : '  (deels: ' . implode(' | ', $waarschuwingen) . ')',
        );
        $gelukt++;
    }
}

printf("\n%s: %d gemeten, %d mislukt\n", date('c'), $gelukt, $mislukt);
exit($mislukt > 0 ? 1 : 0);
