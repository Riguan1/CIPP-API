<?php
declare(strict_types=1);

/**
 * Het rapport dat de klant kan downloaden.
 *
 *   rapport.php?t=<token>                 opmaak voor scherm en printen (print naar pdf)
 *   rapport.php?t=<token>&formaat=json    het hele dossier als json-bestand
 *
 * Dezelfde ondertekende link als de klantweergave, dus wie het rapport kan openen, kan zijn eigen
 * dossier al zien.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;
use CbwPortal\Controls;
use CbwPortal\Stand;

$config = Config::laden();
$token = (string)($_GET['t'] ?? '');
$clientId = $config->link()->controleer($token);

if ($clientId === null) {
    http_response_code(403);
    exit('Deze link is verlopen of ongeldig.');
}

$dossier = $config->dossier();
$klant = $dossier->klant($clientId);

if ($klant === null) {
    http_response_code(404);
    exit('Dit dossier is nog niet ingericht.');
}

$stand = Stand::voor($dossier, $clientId);
$opgehaald = $dossier->stand($clientId);
$samenvatting = $stand->samenvatting();
$percentage = $stand->percentage();
$bestandsnaam = preg_replace('/[^a-z0-9]+/', '-', strtolower((string)$klant['naam'])) . '-cyberbeveiligingswet-' . date('Y-m-d');

// --- json-uitvoer -------------------------------------------------------------------------------
if (($_GET['formaat'] ?? '') === 'json') {
    $regels = [];
    foreach (Controls::plat() as $id => $controle) {
        $bevinding = $stand->bevinding($id);
        $antwoord = $stand->antwoord($id);
        $regels[] = [
            'controle'      => $id,
            'artikel'       => 'art. 21 lid 2 ' . $controle['letter'],
            'onderwerp'     => $controle['thema'],
            'omschrijving'  => $controle['tekst'],
            'kernpunt'      => $controle['kern'],
            'status'        => $stand->effectief($id),
            'bron'          => $bevinding !== null ? 'meting' : ($antwoord['status'] !== null ? 'vastgelegd' : null),
            'meting'        => $bevinding,
            'eigen_antwoord'=> $antwoord,
            'overschreven'  => $stand->overschreven($id),
            'niet_meetbaar' => $stand->nietMeetbaar($id),
        ];
    }

    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $bestandsnaam . '.json"');
    echo json_encode([
        'organisatie'  => $klant['naam'],
        'opgesteld_op' => date('c'),
        'gemeten_op'   => $opgehaald['opgehaald'],
        'percentage'   => $percentage,
        'samenvatting' => $samenvatting,
        'controles'    => $regels,
        'toelichting'  => 'Stand van zaken rond de zorgplicht van de Cyberbeveiligingswet (artikel 21 lid 2 NIS2). '
                        . 'Metingen tonen wat op het genoemde moment aantoonbaar was; vastgelegde antwoorden zijn '
                        . 'door de organisatie zelf opgegeven. Geen juridisch advies, geen formele toets.',
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function h(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function kleur(int $pct): string
{
    return $pct >= 80 ? '#1a7a55' : ($pct >= 40 ? '#8d5c0e' : '#a8322c');
}

$label = ['geregeld' => 'Geregeld', 'deels' => 'Deels', 'open' => 'Niet geregeld', 'nvt' => 'N.v.t.'];
?>
<!doctype html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyberbeveiligingswet &mdash; <?= h($klant['naam']) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;600&family=Source+Serif+4:opsz,wght@8..60,400;8..60,600&display=swap">
<style>
:root{--accent:<?= h((string)$config->get('accent')) ?>; --ink:#141a21; --ink-2:#465061; --ink-3:#6f7987;
  --line:#d7dce4; --line-2:#ebeef3; --ok:#1a7a55; --warn:#8d5c0e; --crit:#a8322c;
  --ok-z:#e2f1ea; --warn-z:#faefda; --crit-z:#fae7e5; --nvt-z:#edf0f3;}
*{box-sizing:border-box}
body{margin:0; background:#e8eaee; color:var(--ink);
  font-family:"Source Serif 4",Georgia,serif; font-size:10.5pt; line-height:1.5}
h1,h2,h3,th,.ui{font-family:Archivo,Arial,sans-serif; margin:0}
.vel{width:210mm; min-height:297mm; margin:0 auto 8mm; padding:16mm 15mm; background:#fff;
  box-shadow:0 2px 6px rgba(0,0,0,.12)}
.balk{display:flex; align-items:baseline; gap:12px; padding-bottom:7px; border-bottom:1.5px solid var(--accent); margin-bottom:14px}
.balk .merk{font-family:Archivo; font-weight:800; font-size:11pt; color:var(--accent)}
.balk .doc{font-family:Archivo; font-size:8pt; letter-spacing:.09em; text-transform:uppercase; color:var(--ink-3); margin-left:auto}
h1{font-size:22pt; font-weight:800; letter-spacing:-.02em; line-height:1.1; margin-bottom:3mm}
h2{font-size:13pt; font-weight:700; margin:7mm 0 2.5mm}
.lead{font-size:11pt; color:var(--ink-2); max-width:150mm; margin:0 0 4mm}
.cijfers{display:grid; grid-template-columns:repeat(4,1fr); gap:4mm; margin:5mm 0}
.cijfer{border:1px solid var(--line); border-radius:2mm; padding:4mm}
.cijfer b{display:block; font-family:"IBM Plex Mono",monospace; font-size:19pt; letter-spacing:-.02em}
.cijfer span{font-family:Archivo; font-size:8pt; color:var(--ink-3); display:block; margin-top:1.5mm; line-height:1.3}
table{width:100%; border-collapse:collapse; font-size:9pt}
th{font-family:Archivo; font-size:7.5pt; font-weight:600; letter-spacing:.06em; text-transform:uppercase;
  color:var(--ink-3); text-align:left; padding:2mm 2mm 1.5mm; border-bottom:1.5px solid var(--line)}
td{padding:1.8mm 2mm; border-bottom:1px solid var(--line-2); vertical-align:top}
td.art{font-family:"IBM Plex Mono",monospace; font-size:8pt; color:var(--ink-3); white-space:nowrap}
td.st{white-space:nowrap; text-align:right}
.pil{font-family:Archivo; font-size:7.5pt; font-weight:700; letter-spacing:.04em; text-transform:uppercase;
  padding:1mm 2mm; border-radius:1mm}
.s-geregeld{background:var(--ok-z); color:var(--ok)}
.s-deels{background:var(--warn-z); color:var(--warn)}
.s-open{background:var(--crit-z); color:var(--crit)}
.s-nvt{background:var(--nvt-z); color:var(--ink-3)}
.s-leeg{background:var(--crit-z); color:var(--crit)}
.kern{font-family:Archivo; font-size:7pt; font-weight:700; text-transform:uppercase; color:var(--crit);
  background:var(--crit-z); padding:.6mm 1.5mm; border-radius:1mm; margin-left:1.5mm}
.bron{font-family:Archivo; font-size:8pt; color:var(--ink-3); display:block; margin-top:.8mm}
.voet{margin-top:8mm; padding-top:3mm; border-top:1px solid var(--line-2); font-size:8.5pt; color:var(--ink-3)}
.knoppen{position:sticky; top:0; z-index:5; background:#fff; border-bottom:1px solid var(--line);
  padding:10px 16px; display:flex; gap:10px; align-items:center; font-family:Archivo; font-size:13px}
.knoppen a, .knoppen button{font-family:Archivo; font-size:13px; font-weight:600; text-decoration:none;
  border:1px solid var(--line); border-radius:6px; padding:7px 12px; color:var(--ink-2); background:#fff; cursor:pointer}
.knoppen .primair{background:var(--accent); border-color:var(--accent); color:#fff}
@media print{
  body{background:#fff}
  .knoppen{display:none}
  .vel{width:auto; min-height:0; margin:0; padding:0; box-shadow:none}
  @page{size:A4; margin:16mm 15mm}
  tr{break-inside:avoid}
  h2{break-after:avoid}
}
</style>
</head>
<body>

<div class="knoppen">
  <strong style="margin-right:auto">Rapport <?= h($klant['naam']) ?></strong>
  <button class="primair" onclick="window.print()">Opslaan als pdf</button>
  <a href="rapport.php?t=<?= h($token) ?>&amp;formaat=json">Download json</a>
  <a href="index.php?t=<?= h($token) ?>">Terug naar het portaal</a>
</div>

<div class="vel">
  <div class="balk">
    <span class="merk"><?= h((string)$config->get('merknaam')) ?></span>
    <span class="doc">Cyberbeveiligingswet &middot; stand van zaken</span>
  </div>

  <h1><?= h($klant['naam']) ?></h1>
  <p class="lead">
    Stand van de zorgplicht uit de Cyberbeveiligingswet: de tien maatregelen van artikel 21 lid 2,
    uitgewerkt in <?= Controls::aantal() ?> controles. Opgesteld op <?= h(date('j F Y')) ?>.
    <?= $opgehaald['opgehaald']
      ? 'De omgeving is gemeten op ' . h(date('j F Y \o\m H:i', strtotime((string)$opgehaald['opgehaald']))) . '.'
      : 'Er is nog geen meting van de omgeving uitgevoerd.' ?>
  </p>

  <div class="cijfers">
    <div class="cijfer"><b style="color:<?= kleur($percentage) ?>"><?= $percentage ?>%</b><span>van de maatregelen geregeld</span></div>
    <div class="cijfer"><b style="color:var(--crit)"><?= $samenvatting['kern_open'] ?></b><span>kernpunten open</span></div>
    <div class="cijfer"><b><?= $samenvatting['open'] ?></b><span>punten te regelen</span></div>
    <div class="cijfer"><b style="color:var(--ok)"><?= $samenvatting['gemeten'] ?></b><span>automatisch gemeten</span></div>
  </div>

  <h2>Wat nog moet gebeuren</h2>
  <?php $openstaand = $stand->openstaand(); ?>
  <?php if ($openstaand === []): ?>
    <p>Geen openstaande punten. Bewaar de onderbouwing per maatregel, want bij toezicht telt wat u kunt aantonen.</p>
  <?php else: ?>
    <table>
      <tr><th style="width:18mm">Artikel</th><th>Maatregel</th><th style="width:26mm">Status</th></tr>
      <?php foreach ($openstaand as $item): ?>
        <tr>
          <td class="art">21.2 <?= h($item['letter']) ?></td>
          <td>
            <?= h($item['tekst']) ?><?= $item['kern'] ? '<span class="kern">kern</span>' : '' ?>
            <span class="bron"><?= h($item['toelichting']) ?></span>
          </td>
          <td class="st"><span class="pil s-<?= h($item['status']) ?>"><?= h($label[$item['status']] ?? $item['status']) ?></span></td>
        </tr>
      <?php endforeach; ?>
    </table>
  <?php endif; ?>

  <h2>Volledige stand per maatregel</h2>
  <table>
    <tr><th style="width:18mm">Artikel</th><th>Maatregel en onderbouwing</th><th style="width:26mm">Status</th></tr>
    <?php foreach (Controls::themas() as $letter => $thema): ?>
      <tr><td colspan="3" style="padding-top:4mm;border-bottom:none">
        <strong class="ui" style="font-size:9.5pt"><?= h($letter) ?>. <?= h($thema['naam']) ?>
          &mdash; <?= $stand->percentageThema($letter) ?>%</strong>
      </td></tr>
      <?php foreach ($thema['controles'] as $id => $controle):
          $effectief = $stand->effectief($id);
          $bevinding = $stand->bevinding($id);
          $antwoord = $stand->antwoord($id);
          $niet = $stand->nietMeetbaar($id); ?>
        <tr>
          <td class="art">21.2 <?= h($letter) ?></td>
          <td>
            <?= h($controle['tekst']) ?><?= $controle['kern'] ? '<span class="kern">kern</span>' : '' ?>
            <?php if ($bevinding && ($bevinding['status'] ?? '') !== 'onbekend'): ?>
              <span class="bron">Gemeten: <?= h($bevinding['kop']) ?> &middot; <?= h($bevinding['bron']) ?><?php
                if ($stand->overschreven($id)) { echo ' &middot; zelf aangepast'; } ?></span>
            <?php elseif ($antwoord['notitie']): ?>
              <span class="bron">Vastgelegd: <?= h($antwoord['notitie']) ?></span>
            <?php elseif ($niet): ?>
              <span class="bron">Niet te meten: <?= h($niet) ?></span>
            <?php endif; ?>
          </td>
          <td class="st">
            <span class="pil s-<?= $effectief ? h($effectief) : 'leeg' ?>"><?= $effectief ? h($label[$effectief]) : 'Onbeantwoord' ?></span>
          </td>
        </tr>
      <?php endforeach; ?>
    <?php endforeach; ?>
  </table>

  <p class="voet">
    Dit rapport geeft de stand op <?= h(date('j F Y')) ?>. Metingen tonen wat op het genoemde moment
    aantoonbaar was in de omgeving; ze bewijzen niet dat een maatregel werkt zoals bedoeld. Antwoorden
    zonder meting zijn door de organisatie zelf vastgelegd. Dit is geen juridisch advies en geen formele
    toets aan de Cyberbeveiligingswet.
  </p>
</div>
</body>
</html>
