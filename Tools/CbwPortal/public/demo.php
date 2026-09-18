<?php
declare(strict_types=1);

/**
 * De etalage: wat wij kunnen aantonen zonder dat iemand een vragenlijst hoeft in te vullen.
 *
 * Openbaar, zonder inloggen en zonder klantgegevens. Bedoeld om aan een prospect te laten zien,
 * of om vanuit de website naar te linken. Alle getallen op deze pagina zijn voorbeelden en staan
 * als zodanig op het scherm.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;
use CbwPortal\Controls;

$config = Config::laden();
$controles = Controls::plat();
$gemeten = array_filter($controles, static fn(array $c) => $c['meetbaar']);
$kern = array_filter($controles, static fn(array $c) => $c['kern']);
$kernGemeten = array_filter($kern, static fn(array $c) => $c['meetbaar']);

// Voorbeeldbevindingen: dit is hoe een regel eruitziet als hij gevuld is.
$voorbeelden = [
    ['j1', 'geregeld', '186 van 190 gebruikers (97,9%) kan MFA gebruiken'],
    ['j3', 'open',     'Geen ingeschakeld beleid gevonden dat verouderde authenticatie blokkeert'],
    ['c1', 'geregeld', '190 van 190 beschermde seats (100%) is de laatste 2 dagen geback-upt'],
    ['c2', 'deels',    '14 van 14 integriteitscontroles geslaagd (laatste 3 dagen geleden)'],
    ['i2', 'deels',    '6 permanente global administrators'],
    ['h2', 'geregeld', '178 van 181 apparaten (98,3%) is versleuteld'],
];

$nietMeetbaar = [
    'b1' => 'Een incidentresponsplan bestaat als document, niet als instelling.',
    'd1' => 'Het leveranciersregister staat buiten elke omgeving die wij uitlezen.',
    'e2' => 'Een externe kwetsbaarhedenscan vraagt een scanner naast Microsoft 365.',
    'f3' => 'Bestuursbesluiten staan in notulen.',
    'g1' => 'Scholing van bestuurders bewijst u met een presentielijst.',
    'j4' => 'Noodcommunicatie is per definitie onafhankelijk van de omgeving die plat ligt.',
];

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<!doctype html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wat wij kunnen aantonen &mdash; Cyberbeveiligingswet</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<link rel="stylesheet" href="stijl.css">
<style>
.hero{padding:40px 0 10px}
.hero h1{font-family:Archivo; font-weight:800; font-size:clamp(28px,4.4vw,42px); line-height:1.08; letter-spacing:-.025em; max-width:20ch}
.hero p{font-size:clamp(16px,1.7vw,19px); color:var(--ink-2); max-width:62ch; margin:14px 0 0}
.telrij{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-top:26px}
.voorbeeldband{font-family:Archivo; font-size:12px; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
  color:var(--warn); background:var(--warn-soft); border:1px solid color-mix(in srgb,var(--warn) 30%,transparent);
  padding:5px 10px; border-radius:99px; display:inline-block}
.bron{font-family:Archivo; font-size:12.5px; color:var(--ink-3)}
.split{display:grid; grid-template-columns:1fr 1fr; gap:16px}
@media (max-width:760px){ .split{grid-template-columns:1fr} }
</style>
</head>
<body>

<header class="topbar">
  <div class="topbar-in">
    <span class="merk"><?= h((string)$config->get('merknaam')) ?></span>
    <span class="klantnaam">Cyberbeveiligingswet &middot; wat wij aantonen</span>
  </div>
</header>

<div class="shell">

  <section class="hero">
    <h1>Uw compliance hoeft geen vragenlijst te zijn</h1>
    <p>
      De zorgplicht van de Cyberbeveiligingswet bestaat uit tien maatregelen, bij ons uitgewerkt in
      <strong><?= count($controles) ?> controles</strong> waarvan <strong><?= count($kern) ?> kernpunten</strong> &mdash; de punten waar een
      toezichthouder als eerste naar vraagt. Van <strong><?= count($gemeten) ?></strong> daarvan lezen wij de stand rechtstreeks
      uit uw omgeving. U ziet dus niet wat u dénkt dat geregeld is, maar wat aantoonbaar zo is.
    </p>
    <div class="telrij">
      <div class="card tegel"><b><?= count($controles) ?></b><span>controles uit artikel 21 lid 2</span></div>
      <div class="card tegel tegel-ok"><b><?= count($gemeten) ?></b><span>automatisch uitgelezen</span></div>
      <div class="card tegel tegel-kern"><b><?= count($kernGemeten) ?></b><span>van de <?= count($kern) ?> kernpunten meten wij zelf</span></div>
      <div class="card tegel"><b>1</b><span>rapport dat u zelf downloadt, wanneer u wilt</span></div>
    </div>
  </section>

  <section class="sec">
    <h2>Wat wij uitlezen</h2>
    <p class="intro">
      Rechtstreeks uit uw Microsoft 365-omgeving en uw back-upoplossing. Elke regel komt met de bron
      en het moment van meten, zodat u het kunt laten zien in plaats van beweren.
    </p>
    <div class="card">
      <table>
        <tr><th style="width:80px">Artikel</th><th>Wat wij vaststellen</th><th style="width:34%">Bron</th></tr>
        <?php foreach ($gemeten as $id => $controle): ?>
          <tr>
            <td class="mono" style="font-size:12px;color:var(--ink-3)">21.2 <?= h($controle['letter']) ?></td>
            <td>
              <?= h($controle['tekst']) ?>
              <?= $controle['kern'] ? '<span class="kern">kern</span>' : '' ?>
            </td>
            <td class="bron"><?= h($controle['bron']) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </section>

  <section class="sec">
    <h2>Zo ziet dat er in uw portaal uit</h2>
    <p class="intro"><span class="voorbeeldband">Voorbeeld &mdash; geen echte gegevens</span></p>
    <div class="card">
      <?php foreach ($voorbeelden as [$id, $status, $kop]):
          $controle = $controles[$id]; ?>
        <div class="ctrl <?= $controle['kern'] ? 'kernrij' : '' ?>">
          <div>
            <p><?= h($controle['tekst']) ?><?= $controle['kern'] ? '<span class="kern">kern</span>' : '' ?></p>
          </div>
          <span class="pil <?= $status === 'geregeld' ? 'p-ok' : ($status === 'deels' ? 'p-deels' : 'p-open') ?>">
            <?= $status === 'geregeld' ? 'geregeld' : ($status === 'deels' ? 'deels' : 'niet geregeld') ?>
          </span>
          <p class="bewijs bewijs-<?= h($status) ?>">
            <b>gemeten</b> <span><?= h($kop) ?></span>
            <em><?= h($controle['bron']) ?></em>
          </p>
        </div>
      <?php endforeach; ?>
    </div>
  </section>

  <section class="sec">
    <div class="split">
      <div>
        <h2>Wat wij niet meten</h2>
        <p class="intro">
          En waarom we dat zeggen in plaats van er een vinkje van te maken. Deze punten blijven uw
          vastlegging; wij houden alleen bij of ze er zijn.
        </p>
        <div class="card">
          <?php foreach ($nietMeetbaar as $id => $reden): ?>
            <div class="actie" style="grid-template-columns:auto 1fr">
              <span class="ref">21.2 <?= h($controles[$id]['letter']) ?></span>
              <span class="wat"><?= h($controles[$id]['tekst']) ?><small><?= h($reden) ?></small></span>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
      <div>
        <h2>Hoe het werkt</h2>
        <p class="intro">Drie koppelingen, één beeld, elke nacht bijgewerkt.</p>
        <div class="card pad flow">
          <p><strong>Uw facturatieomgeving</strong> levert wie u bent; u logt in waar u altijd inlogt en klikt door.</p>
          <p><strong>Uw Microsoft 365-omgeving</strong> levert de techniek: MFA, versleuteling, beheerdersaccounts,
            patchstand, logging, toegang.</p>
          <p><strong>Uw back-upoplossing</strong> levert het bewijs dat er buiten de omgeving een kopie ligt en dat
            die leesbaar is.</p>
          <p style="margin-bottom:0"><strong>De rest legt u zelf vast</strong>, één keer, met een notitie waar het bewijs
            staat. Dat telt even zwaar mee in het percentage &mdash; anders zou het getal een halve waarheid zijn.</p>
        </div>
      </div>
    </div>
  </section>

  <section class="sec">
    <div class="card pad">
      <h2 style="font-size:18px">Wat u eraan heeft</h2>
      <p style="color:var(--ink-2);max-width:65ch">
        U ziet op elk moment waar u staat, wat er nog moet gebeuren en in welke volgorde. U downloadt er
        een rapport van wanneer uw bestuur, uw verzekeraar of een klant erom vraagt. En u merkt het als
        iets wegzakt: een beheerder zonder MFA, een back-up die stilvalt, een laptop die niet meer
        versleuteld is.
      </p>
      <p class="voet" style="margin-top:14px">
        Een hulpmiddel om aantoonbaar in control te zijn &mdash; geen juridisch advies en geen formele toets
        aan de Cyberbeveiligingswet. Een meting toont wat op dat moment aantoonbaar was, niet dat een
        maatregel werkt zoals bedoeld.
      </p>
    </div>
  </section>
</div>
</body>
</html>
