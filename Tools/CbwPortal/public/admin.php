<?php
declare(strict_types=1);

/**
 * Beheerweergave voor de MSP: alle HostBill-klanten, hun koppeling aan een tenant, hun stand,
 * en de link die de klant te zien krijgt.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;
use CbwPortal\Controls;
use CbwPortal\Meting;
use CbwPortal\Stand;

$config = Config::laden();

session_start();
$wachtwoord = (string)$config->get('admin_wachtwoord', '');

if ($wachtwoord === '') {
    http_response_code(500);
    exit('Stel eerst admin_wachtwoord in. Zonder wachtwoord blijft deze pagina dicht.');
}

if (isset($_POST['wachtwoord'])) {
    if (hash_equals($wachtwoord, (string)$_POST['wachtwoord'])) {
        $_SESSION['cbw_admin'] = true;
        session_regenerate_id(true);
    } else {
        $loginFout = 'Onjuist wachtwoord.';
        // Een mislukte poging mag niet gratis zijn.
        sleep(1);
    }
}

if (($_SESSION['cbw_admin'] ?? false) !== true) {
    toonLogin($loginFout ?? null);
    exit;
}

$dossier = $config->dossier();
$melding = null;
$fout = null;

// --- acties ------------------------------------------------------------------------------------
try {
    if (($_POST['actie'] ?? '') === 'koppel') {
        $clientId = (string)$_POST['client_id'];
        $tenant = trim((string)$_POST['tenant']);
        $backupRef = trim((string)($_POST['backup_ref'] ?? ''));
        $dossier->klantOpslaan(
            $clientId,
            $tenant !== '' ? $tenant : null,
            (string)$_POST['naam'],
            (string)($_POST['in_scope'] ?? 'onbekend'),
            null,
            $backupRef !== '' ? $backupRef : null,
        );
        $melding = 'Koppeling opgeslagen.';
    }

    if (($_POST['actie'] ?? '') === 'ververs') {
        $clientId = (string)$_POST['client_id'];
        $klant = $dossier->klant($clientId);
        if ($klant === null || !$klant['tenant']) {
            $fout = 'Koppel deze klant eerst aan een tenant.';
        } else {
            $vorige = $dossier->stand($clientId)['stand'];
            ['stand' => $stand, 'waarschuwingen' => $waarschuwingen, 'gemeten' => $nieuw] =
                (new Meting($config))->voorKlant($klant, $vorige);

            if ($stand === null || $nieuw === 0) {
                $dossier->standOpslaan($clientId, $stand, implode(' | ', $waarschuwingen));
                $fout = 'Geen nieuwe gegevens opgehaald. ' . implode(' | ', $waarschuwingen);
            } else {
                $dossier->standOpslaan($clientId, $stand, $waarschuwingen === [] ? null : implode(' | ', $waarschuwingen));
                $bruikbaar = count(array_filter($stand['bevindingen'], static fn($b) => $b['status'] !== 'onbekend'));
                $melding = "Stand opgehaald: {$nieuw} bevindingen binnen, {$bruikbaar} bruikbaar.";
                if ($waarschuwingen !== []) {
                    $fout = 'Deels gelukt - ' . implode(' | ', $waarschuwingen);
                }
            }
        }
    }

    if (($_POST['actie'] ?? '') === 'importeer') {
        $aantal = 0;
        foreach ($config->hostbill()->klanten() as $hb) {
            if ($dossier->klant($hb['id']) !== null) {
                continue;
            }
            $naam = $hb['bedrijf'] !== '' ? $hb['bedrijf'] : $hb['naam'];
            $tenant = null;
            try {
                $detail = $config->hostbill()->klant($hb['id']);
                $tenant = $config->hostbill()->tenantUitKlant($detail, (string)$config->get('hostbill_veld'));
            } catch (Throwable) {
                // Geen detail beschikbaar: de klant komt zonder tenant binnen en wordt hier gekoppeld.
            }
            $dossier->klantOpslaan($hb['id'], $tenant, $naam);
            $aantal++;
        }
        $melding = $aantal === 0 ? 'Geen nieuwe klanten gevonden.' : "{$aantal} klanten uit HostBill toegevoegd.";
    }
} catch (Throwable $e) {
    $fout = $e->getMessage();
}

$backupNaam = null;
try {
    $bron = $config->backupBron();
    $backupNaam = $bron?->naam();
} catch (Throwable) {
    // Onvolledig ingestelde bron: de kolom blijft dan uitgeschakeld.
}

$klanten = $dossier->klanten();
$link = $config->link();
$basis = (string)$config->get('portaal_url', rtrim(dirname((string)($_SERVER['REQUEST_URI'] ?? '/')), '/'));

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function kleur(int $pct): string
{
    return $pct >= 80 ? 'var(--ok)' : ($pct >= 40 ? 'var(--warn)' : 'var(--crit)');
}

function toonLogin(?string $fout): void
{
    $f = $fout ? '<p class="melding melding-fout">' . htmlspecialchars($fout, ENT_QUOTES) . '</p>' : '';
    echo <<<HTML
    <!doctype html><html lang="nl"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Beheer</title><link rel="stylesheet" href="stijl.css"></head><body>
    <div class="shell" style="max-width:380px">
      <div class="card pad">
        <h2 style="margin-bottom:12px">Beheer</h2>
        {$f}
        <form method="post" style="display:flex;flex-direction:column;gap:10px">
          <input type="password" name="wachtwoord" placeholder="Wachtwoord" autofocus>
          <button class="knop primair" type="submit">Inloggen</button>
        </form>
      </div>
    </div></body></html>
    HTML;
}
?>
<!doctype html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cbw-portaal &mdash; beheer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=IBM+Plex+Mono:wght@400;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<link rel="stylesheet" href="stijl.css">
</head>
<body>

<header class="topbar">
  <div class="topbar-in">
    <span class="merk"><?= h((string)$config->get('merknaam')) ?> &mdash; beheer</span>
    <a href="diagnose.php" class="klantnaam">Verbindingen testen</a>
  </div>
</header>

<div class="shell">
  <?php if ($melding): ?><p class="melding melding-ok"><?= h($melding) ?></p><?php endif; ?>
  <?php if ($fout): ?><p class="melding melding-fout"><?= h($fout) ?></p><?php endif; ?>

  <section class="sec">
    <div style="display:flex;align-items:baseline;gap:16px;flex-wrap:wrap">
      <h2>Klanten</h2>
      <form method="post" style="margin-left:auto">
        <input type="hidden" name="actie" value="importeer">
        <button class="knop" type="submit">Klanten uit HostBill ophalen</button>
      </form>
    </div>
    <p class="intro">
      Elke klant heeft een tenant nodig voordat er gemeten kan worden. Staat het veld
      &ldquo;<?= h((string)$config->get('hostbill_veld')) ?>&rdquo; ingevuld in HostBill, dan wordt het bij het ophalen overgenomen.
    </p>

    <div class="card">
      <table>
        <tr>
          <th>Klant</th><th>Tenant</th><th>Back-up</th><th>Scope</th><th>Stand</th><th>Open</th><th>Gemeten</th><th></th>
        </tr>
        <?php if ($klanten === []): ?>
          <tr><td colspan="8" class="leeg">Nog geen klanten. Haal ze op uit HostBill.</td></tr>
        <?php endif; ?>
        <?php foreach ($klanten as $klant):
            $clientId = (string)$klant['client_id'];
            $stand = Stand::voor($dossier, $clientId);
            $sam = $stand->samenvatting();
            $pct = $stand->percentage();
            $opgehaald = $dossier->stand($clientId); ?>
          <tr>
            <td>
              <strong><?= h($klant['naam']) ?></strong><br>
              <span class="mono" style="font-size:11.5px;color:var(--ink-3)">#<?= h($clientId) ?></span>
            </td>
            <td>
              <form method="post" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="actie" value="koppel">
                <input type="hidden" name="client_id" value="<?= h($clientId) ?>">
                <input type="hidden" name="naam" value="<?= h($klant['naam']) ?>">
                <input type="hidden" name="in_scope" value="<?= h($klant['in_scope']) ?>">
                <input type="hidden" name="backup_ref" value="<?= h($klant['backup_ref'] ?? '') ?>">
                <input type="text" name="tenant" value="<?= h($klant['tenant']) ?>" placeholder="klant.onmicrosoft.com" style="min-width:190px">
                <button class="knop" type="submit">Bewaar</button>
              </form>
            </td>
            <td>
              <form method="post" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="actie" value="koppel">
                <input type="hidden" name="client_id" value="<?= h($clientId) ?>">
                <input type="hidden" name="naam" value="<?= h($klant['naam']) ?>">
                <input type="hidden" name="tenant" value="<?= h($klant['tenant']) ?>">
                <input type="hidden" name="in_scope" value="<?= h($klant['in_scope']) ?>">
                <input type="text" name="backup_ref" value="<?= h($klant['backup_ref'] ?? '') ?>"
                       placeholder="<?= $backupNaam ? h($backupNaam) . '-id' : 'geen bron' ?>" style="min-width:130px"
                       title="Organisatie-id bij de back-upbron" <?= $backupNaam ? '' : 'disabled' ?>>
                <button class="knop" type="submit" <?= $backupNaam ? '' : 'disabled' ?>>Bewaar</button>
              </form>
            </td>
            <td>
              <form method="post">
                <input type="hidden" name="actie" value="koppel">
                <input type="hidden" name="client_id" value="<?= h($clientId) ?>">
                <input type="hidden" name="naam" value="<?= h($klant['naam']) ?>">
                <input type="hidden" name="tenant" value="<?= h($klant['tenant']) ?>">
                <input type="hidden" name="backup_ref" value="<?= h($klant['backup_ref'] ?? '') ?>">
                <select name="in_scope" onchange="this.form.submit()">
                  <?php foreach (['onbekend' => 'Onbekend', 'essentieel' => 'Essentieel', 'belangrijk' => 'Belangrijk', 'buiten' => 'Buiten scope'] as $w => $l): ?>
                    <option value="<?= $w ?>" <?= $klant['in_scope'] === $w ? 'selected' : '' ?>><?= $l ?></option>
                  <?php endforeach; ?>
                </select>
              </form>
            </td>
            <td>
              <span class="mini"><i style="width:<?= $pct ?>%;background:<?= kleur($pct) ?>"></i></span>
              <span class="mono" style="font-size:12px"><?= $pct ?>%</span>
            </td>
            <td>
              <?php if ($sam['kern_open'] > 0): ?>
                <span class="pil p-open"><?= $sam['kern_open'] ?> kern</span>
              <?php elseif ($sam['open'] > 0): ?>
                <span class="pil p-deels"><?= $sam['open'] ?> open</span>
              <?php else: ?>
                <span class="pil p-ok">rond</span>
              <?php endif; ?>
            </td>
            <td>
              <?php if ($opgehaald['fout']): ?>
                <span class="pil p-open" title="<?= h($opgehaald['fout']) ?>">fout</span>
              <?php elseif ($opgehaald['opgehaald']): ?>
                <span style="font-size:13px;color:var(--ink-3)"><?= h(date('j M H:i', strtotime((string)$opgehaald['opgehaald']))) ?></span>
              <?php else: ?>
                <span style="font-size:13px;color:var(--ink-3)">nooit</span>
              <?php endif; ?>
            </td>
            <td style="white-space:nowrap">
              <form method="post" style="display:inline">
                <input type="hidden" name="actie" value="ververs">
                <input type="hidden" name="client_id" value="<?= h($clientId) ?>">
                <button class="knop" type="submit" <?= $klant['tenant'] ? '' : 'disabled' ?>>Meet</button>
              </form>
              <a class="knop" style="text-decoration:none;display:inline-block"
                 href="<?= h($link->url($basis, $clientId)) ?>">Klantweergave</a>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </section>

  <section class="sec">
    <p class="voet">
      De knop <strong>Meet</strong> haalt de stand nu op; normaal doet <span class="mono">bin/sync.php</span> dat elke nacht
      via cron. Mislukt een meting, dan blijft de laatst bekende stand staan &mdash; de klant ziet dan de datum
      erbij, nooit een groen vinkje dat nergens op steunt. De klantweergave opent met een ondertekende link
      die <?= (int)round(((int)$config->get('link_geldig')) / 86400) ?> dagen geldig is; vanuit HostBill krijgt de klant er elke keer een verse.
      De controles volgen de zorgplicht van artikel 21 lid 2 NIS2: <?= Controls::aantal() ?> stuks.
      <?= $backupNaam
        ? 'Back-ups worden uitgelezen uit ' . h($backupNaam) . '; vul per klant het organisatie-id in.'
        : 'Er is geen back-upbron ingesteld, dus c1 en c2 blijven handwerk.' ?>
    </p>
  </section>
</div>
</body>
</html>
