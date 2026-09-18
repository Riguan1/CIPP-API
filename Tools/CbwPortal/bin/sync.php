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
use CbwPortal\Meting;

$config = Config::laden();
$dossier = $config->dossier();
$meting = new Meting($config);

if ($config->backupBron() === null) {
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
    // Zonder tenant kan CIPP niets, maar de incidentregistratie uit HostBill nog wel: dus meten we
    // toch, en zeggen we erbij wat er ontbreekt.
    if ($tenant === '') {
        printf("let op        %-24s geen tenant gekoppeld, alleen HostBill\n", $klant['naam']);
    }

    $vorige = $dossier->stand($clientId)['stand'];
    ['stand' => $stand, 'waarschuwingen' => $waarschuwingen, 'gemeten' => $nieuw] = $meting->voorKlant($klant, $vorige);

    // Niets nieuws binnengekregen telt als mislukt, ook als er nog een oude stand ligt: anders
    // meldt de cron 'gemeten' terwijl er dagen niets is opgehaald.
    if ($stand !== null && $nieuw === 0) {
        $dossier->standOpslaan($clientId, $stand, implode(' | ', $waarschuwingen));
        printf("MISLUKT       %-24s geen nieuwe gegevens; vorige stand blijft staan\n", $klant['naam']);
        $mislukt++;
        continue;
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
