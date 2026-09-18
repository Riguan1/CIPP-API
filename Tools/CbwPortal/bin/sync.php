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

    try {
        $stand = $cipp->stand($tenant);
        $dossier->standOpslaan($clientId, $stand);
        $bruikbaar = count(array_filter($stand['bevindingen'], static fn($b) => $b['status'] !== 'onbekend'));
        printf("gemeten       %-24s %d bevindingen, %d bruikbaar\n", $klant['naam'], count($stand['bevindingen']), $bruikbaar);
        $gelukt++;
    } catch (Throwable $e) {
        $dossier->standOpslaan($clientId, null, $e->getMessage());
        printf("MISLUKT       %-24s %s\n", $klant['naam'], $e->getMessage());
        $mislukt++;
    }
}

printf("\n%s: %d gemeten, %d mislukt\n", date('c'), $gelukt, $mislukt);
exit($mislukt > 0 ? 1 : 0);
