<?php
declare(strict_types=1);

/**
 * Brug van HostBill naar het Cbw-portaal.
 *
 * Plaats dit bestand in de webroot van HostBill (naast index.php) en zet in het klantenpaneel een
 * menu-item dat ernaar wijst. De ingelogde klant wordt doorgestuurd naar het portaal met een link
 * die door HostBill is ondertekend, zodat het portaal weet wie er kijkt zonder de sessie van
 * HostBill te hoeven kennen.
 *
 *   HostBill  ->  ga-naar-portaal.php  ->  portaal/index.php?t=<clientid>.<verval>.<handtekening>
 *
 * Instellen: vul PORTAAL_URL en GEDEELD_GEHEIM hieronder. Het geheim is hetzelfde als link_secret
 * in de configuratie van het portaal. Deel het met niemand anders: wie het heeft, kan een link
 * voor elke klant maken.
 *
 * Dit is het enige bestand dat iets van HostBill van binnen aanraakt, namelijk het klantnummer in
 * de sessie. De sleutel daarvan verschilt per HostBill-versie, dus we proberen de bekende varianten
 * en zeggen het eerlijk als geen ervan past - dan is het een kwestie van de juiste sleutel hier
 * invullen, niet van zoeken in het portaal.
 */

const PORTAAL_URL    = 'https://portaal.voorbeeld.nl';
const GEDEELD_GEHEIM = 'zet-hier-hetzelfde-geheim-als-link_secret';
const GELDIG_SECONDEN = 3600 * 12;

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$clientId = klantnummerUitSessie();

if ($clientId === null) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit(
        "U bent niet ingelogd, of dit bestand herkent het klantnummer niet in de sessie van deze " .
        "HostBill-versie.\n\n" .
        "Voor de beheerder: kijk met var_dump(\$_SESSION) welke sleutel het klantnummer bevat en " .
        "voeg die toe aan de lijst in klantnummerUitSessie().\n"
    );
}

$verlooptOp = time() + GELDIG_SECONDEN;
$nuttig = $clientId . '.' . $verlooptOp;
$handtekening = rtrim(strtr(base64_encode(
    hash_hmac('sha256', $nuttig, GEDEELD_GEHEIM, true)
), '+/', '-_'), '=');

header('Location: ' . rtrim(PORTAAL_URL, '/') . '/index.php?t=' . rawurlencode($nuttig . '.' . $handtekening));
exit;

/**
 * Haalt het klantnummer uit de HostBill-sessie. Geeft null terug als niets past - nooit een gok,
 * want een verkeerd klantnummer laat de ene klant het dossier van de andere zien.
 */
function klantnummerUitSessie(): ?string
{
    $sleutels = ['clientid', 'client_id', 'cid', 'uid', 'userid', 'hb_clientid'];

    foreach ($sleutels as $sleutel) {
        $waarde = $_SESSION[$sleutel] ?? null;

        // Sommige versies bewaren een array met klantgegevens in plaats van een los nummer.
        if (is_array($waarde)) {
            $waarde = $waarde['id'] ?? $waarde['clientid'] ?? null;
        }

        if (is_scalar($waarde) && ctype_digit((string)$waarde) && (int)$waarde > 0) {
            return (string)(int)$waarde;
        }
    }

    return null;
}
