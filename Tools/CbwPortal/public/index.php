<?php
declare(strict_types=1);

/**
 * Klantweergave: hoe ver is deze klant, en wat moet er nog gebeuren.
 *
 * Toegang loopt via een ondertekende link uit de HostBill-module (?t=...). Het portaal kent de
 * sessie van HostBill niet; de handtekening is het bewijs dat HostBill de bezoeker heeft
 * geïdentificeerd.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;
use CbwPortal\Controls;
use CbwPortal\Stand;

$config = Config::laden();
$link = $config->link();

$token = (string)($_GET['t'] ?? $_POST['t'] ?? '');
$clientId = $link->controleer($token);

if ($clientId === null) {
    http_response_code(403);
    toonFout(
        'Deze link is verlopen of ongeldig',
        'Open het portaal opnieuw vanuit uw klantenpaneel, dan krijgt u een verse link. ' .
        'Lukt dat niet, neem dan contact met ons op.',
        $config,
    );
    exit;
}

$dossier = $config->dossier();
$klant = $dossier->klant($clientId);

if ($klant === null) {
    http_response_code(404);
    toonFout(
        'Dit dossier is nog niet ingericht',
        'Uw beheerder moet dit account eerst koppelen aan een omgeving. Wij hebben daar bericht van gekregen.',
        $config,
    );
    exit;
}

// --- bewerking opslaan -------------------------------------------------------------------------
$melding = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $controle = (string)($_POST['controle'] ?? '');
    $controles = Controls::plat();

    if (isset($controles[$controle])) {
        $status = (string)($_POST['status'] ?? '');
        $huidig = $dossier->antwoorden($clientId)[$controle]['status'] ?? null;

        // Nogmaals op dezelfde knop drukken maakt het antwoord weer leeg: dan telt de meting weer.
        $nieuw = ($status !== '' && $status === $huidig) ? null : ($status !== '' ? $status : null);
        $notitie = trim((string)($_POST['notitie'] ?? ''));

        $dossier->antwoordOpslaan($clientId, $controle, $nieuw, $notitie !== '' ? $notitie : null, 'klant');
        $melding = 'Opgeslagen.';
    }

    // Na POST omleiden, zodat vernieuwen niet opnieuw opslaat.
    header('Location: index.php?t=' . rawurlencode($token) . '#' . $controle);
    exit;
}

$stand = Stand::voor($dossier, $clientId);
$opgehaald = $dossier->stand($clientId);
$samenvatting = $stand->samenvatting();
$openstaand = $stand->openstaand();
$percentage = $stand->percentage();

$merk = (string)$config->get('merknaam');
$accent = (string)$config->get('accent');

/** @return string kleurtoken op basis van een percentage */
function kleur(int $pct): string
{
    return $pct >= 80 ? 'var(--ok)' : ($pct >= 40 ? 'var(--warn)' : 'var(--crit)');
}

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function toonFout(string $titel, string $tekst, Config $config): void
{
    $merk = htmlspecialchars((string)$config->get('merknaam'), ENT_QUOTES);
    echo <<<HTML
    <!doctype html><html lang="nl"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Cyberbeveiligingswet</title><link rel="stylesheet" href="stijl.css"></head><body>
    <header class="topbar"><div class="topbar-in"><span class="merk">{$merk}</span></div></header>
    <div class="shell"><div class="card pad">
      <h2>{$titel}</h2><p style="color:var(--ink-2)">{$tekst}</p>
    </div></div></body></html>
    HTML;
}
?>
<!doctype html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyberbeveiligingswet &mdash; uw stand</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=IBM+Plex+Mono:wght@400;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<link rel="stylesheet" href="stijl.css">
<style>:root{--accent:<?= h($accent) ?>}</style>
</head>
<body>

<header class="topbar">
  <div class="topbar-in">
    <span class="merk"><?= h($merk) ?></span>
    <span class="klantnaam"><?= h($klant['naam']) ?></span>
    <div class="meter" title="Aandeel maatregelen dat geregeld is">
      <span class="meter-track"><i class="meter-fill" style="width:<?= $percentage ?>%;background:<?= kleur($percentage) ?>"></i></span>
      <span class="meter-num"><?= $percentage ?>%</span>
    </div>
  </div>
</header>

<div class="shell">

  <?php if ($melding): ?><p class="melding melding-ok"><?= h($melding) ?></p><?php endif; ?>

  <section class="sec">
    <h2>Waar u staat</h2>
    <p class="intro">
      Dit overzicht volgt de zorgplicht van de Cyberbeveiligingswet: de tien maatregelen van
      artikel 21, uitgewerkt in <?= Controls::aantal() ?> controles. Wat wij in uw omgeving kunnen meten, vullen wij
      automatisch in. De rest beantwoordt u zelf &mdash; en dat telt even zwaar.
    </p>
    <div class="tegels">
      <div class="card tegel"><b style="color:<?= kleur($percentage) ?>"><?= $percentage ?>%</b><span>van de maatregelen geregeld</span></div>
      <div class="card tegel tegel-kern"><b><?= $samenvatting['kern_open'] ?></b><span>kernpunten open &mdash; hier vraagt een toezichthouder het eerst naar</span></div>
      <div class="card tegel"><b><?= $samenvatting['open'] ?></b><span>punten in totaal nog te regelen</span></div>
      <div class="card tegel tegel-ok"><b><?= $samenvatting['gemeten'] ?></b><span>controles automatisch gemeten in uw omgeving</span></div>
    </div>
  </section>

  <?php if ($opgehaald['fout']): ?>
    <p class="melding melding-let">
      De laatste meting van uw omgeving is niet gelukt<?= $opgehaald['opgehaald'] ? '; hieronder staat de stand van ' . h(date('j F Y', strtotime((string)$opgehaald['opgehaald']))) : '' ?>.
      Wij hebben hier bericht van en pakken het op.
    </p>
  <?php elseif ($opgehaald['opgehaald']): ?>
    <p class="voet">Uw omgeving is voor het laatst gemeten op <?= h(date('j F Y \o\m H:i', strtotime((string)$opgehaald['opgehaald']))) ?>.</p>
  <?php endif; ?>

  <section class="sec">
    <h2>Wat u nog moet regelen</h2>
    <p class="intro">Op volgorde van urgentie. Kernpunten eerst, en daarbinnen wat helemaal nog niet geregeld is.</p>
    <div class="card">
      <?php if ($openstaand === []): ?>
        <div class="leeg">Alles staat op geregeld of niet van toepassing. Houd het zo: leg vast waar het bewijs staat, want bij toezicht telt wat u kunt aantonen.</div>
      <?php else: foreach ($openstaand as $item): ?>
        <div class="actie">
          <span class="ref">art. 21.2 <?= h($item['letter']) ?></span>
          <span class="wat">
            <a href="#<?= h($item['id']) ?>" style="color:inherit;text-decoration:none"><?= h($item['tekst']) ?></a>
            <?= $item['kern'] ? '<span class="kern">kern</span>' : '' ?>
            <small><?= h($item['toelichting']) ?></small>
          </span>
          <span class="pil <?= $item['status'] === 'deels' ? 'p-deels' : 'p-open' ?>">
            <?= $item['status'] === 'deels' ? 'deels' : 'niet geregeld' ?>
          </span>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </section>

  <section class="sec">
    <h2>De volledige check</h2>
    <p class="intro">
      Klik een status aan om hem te wijzigen; nogmaals klikken maakt hem weer leeg. Waar wij een meting
      hebben, ziet u die eronder staan. Wijkt uw eigen antwoord daarvan af, dan telt uw antwoord.
    </p>

    <?php foreach (Controls::themas() as $letter => $thema):
        $pctThema = $stand->percentageThema($letter); ?>
      <div class="card" style="margin-bottom:14px">
        <div class="thema-head">
          <span class="letter"><?= h($letter) ?></span>
          <h3><?= h($thema['naam']) ?></h3>
          <span class="thema-bar"><i style="width:<?= $pctThema ?>%;background:<?= kleur($pctThema) ?>"></i></span>
          <span class="thema-pct"><?= $pctThema ?>%</span>
        </div>

        <?php foreach ($thema['controles'] as $id => $controle):
            $effectief = $stand->effectief($id);
            $antwoord = $stand->antwoord($id);
            $bevinding = $stand->bevinding($id);
            $niet = $stand->nietMeetbaar($id); ?>
          <div class="ctrl <?= $controle['kern'] ? 'kernrij' : '' ?>" id="<?= h($id) ?>">
            <div>
              <p><?= h($controle['tekst']) ?><?= $controle['kern'] ? '<span class="kern">kern</span>' : '' ?></p>
            </div>

            <form method="post" class="seg bewerk">
              <input type="hidden" name="t" value="<?= h($token) ?>">
              <input type="hidden" name="controle" value="<?= h($id) ?>">
              <input type="hidden" name="notitie" value="<?= h($antwoord['notitie']) ?>">
              <?php foreach (['geregeld' => 'Geregeld', 'deels' => 'Deels', 'open' => 'Niet', 'nvt' => 'N.v.t.'] as $waarde => $label):
                  $handmatigAan = $antwoord['status'] === $waarde;
                  $autoAan = $antwoord['status'] === null && $bevinding && ($bevinding['status'] ?? '') === $waarde; ?>
                <button type="submit" name="status" value="<?= $waarde ?>"
                        class="<?= $handmatigAan ? 'aan' : ($autoAan ? 'aan auto' : '') ?>"><?= $label ?></button>
              <?php endforeach; ?>
            </form>

            <?php if ($bevinding): ?>
              <p class="bewijs bewijs-<?= h($bevinding['status'] ?: 'onbekend') ?>">
                <b>gemeten</b> <span><?= h($bevinding['kop']) ?></span>
                <?php if ($stand->overschreven($id)): ?><span class="overschreven">u heeft dit zelf aangepast</span><?php endif; ?>
                <em><?= h($bevinding['bron']) ?></em>
              </p>
            <?php elseif ($niet): ?>
              <p class="bewijs"><b>zelf vastleggen</b> <span><?= h($niet) ?></span></p>
            <?php endif; ?>

            <form method="post" class="notitie bewerk">
              <input type="hidden" name="t" value="<?= h($token) ?>">
              <input type="hidden" name="controle" value="<?= h($id) ?>">
              <input type="hidden" name="status" value="<?= h($antwoord['status']) ?>">
              <input type="text" name="notitie" value="<?= h($antwoord['notitie']) ?>"
                     placeholder="Notitie of vindplaats van het bewijs" aria-label="Notitie bij <?= h($controle['tekst']) ?>">
              <button type="submit" class="knop">Bewaar</button>
            </form>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endforeach; ?>
  </section>

  <section class="sec">
    <p class="voet">
      Dit portaal is een hulpmiddel om samen bij te houden waar u staat. Het is geen juridisch advies en
      geen formele toets aan de Cyberbeveiligingswet. Metingen komen uit uw Microsoft 365-omgeving en
      tonen wat op dat moment aantoonbaar was; alles wat wij niet kunnen meten, blijft uw eigen
      vastlegging. Vragen over een punt? Neem contact met ons op &mdash; daar zijn wij voor.
    </p>
  </section>
</div>
</body>
</html>
