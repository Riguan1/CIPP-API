<?php
declare(strict_types=1);

/**
 * Verbindingstest. Zegt per koppeling wat er misgaat en waar je het oplost, in plaats van een
 * blanco scherm.
 */

require __DIR__ . '/../src/bootstrap.php';

use CbwPortal\Config;

session_start();
if (($_SESSION['cbw_admin'] ?? false) !== true) {
    header('Location: admin.php');
    exit;
}

$config = Config::laden();
$resultaten = [];

try {
    $resultaten['HostBill'] = $config->hostbill()->test();
} catch (Throwable $e) {
    $resultaten['HostBill'] = ['ok' => false, 'bericht' => $e->getMessage()];
}

$tenant = trim((string)($_GET['tenant'] ?? ''));
if ($tenant !== '') {
    try {
        $resultaten['CIPP'] = $config->cipp()->test($tenant);
    } catch (Throwable $e) {
        $resultaten['CIPP'] = ['ok' => false, 'bericht' => $e->getMessage()];
    }
}

try {
    $config->dossier();
    $resultaten['Database'] = ['ok' => true, 'bericht' => 'Schema aanwezig en schrijfbaar.'];
} catch (Throwable $e) {
    $resultaten['Database'] = ['ok' => false, 'bericht' => $e->getMessage()];
}

$resultaten['Ondertekening'] = ((string)$config->get('link_secret', '')) === ''
    ? ['ok' => false, 'bericht' => 'link_secret ontbreekt. Zonder geheim zijn klantlinks te vervalsen.']
    : ['ok' => true, 'bericht' => 'Geheim ingesteld. Zet hetzelfde geheim in de HostBill-module.'];

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verbindingen testen</title>
<link rel="stylesheet" href="stijl.css">
</head>
<body>
<header class="topbar"><div class="topbar-in">
  <span class="merk">Verbindingen testen</span>
  <a href="admin.php" class="klantnaam">Terug naar beheer</a>
</div></header>

<div class="shell">
  <section class="sec">
    <h2>Koppelingen</h2>
    <p class="intro">Elke regel test één verbinding. Een fout vertelt waar je hem oplost.</p>
    <div class="card">
      <table>
        <tr><th>Koppeling</th><th>Uitkomst</th></tr>
        <?php foreach ($resultaten as $naam => $r): ?>
          <tr>
            <td><strong><?= h($naam) ?></strong></td>
            <td>
              <span class="pil <?= $r['ok'] ? 'p-ok' : 'p-open' ?>"><?= $r['ok'] ? 'goed' : 'fout' ?></span>
              <div style="margin-top:6px;font-size:14px;color:var(--ink-2)"><?= h($r['bericht']) ?></div>
            </td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </section>

  <section class="sec">
    <h2>CIPP testen op een tenant</h2>
    <p class="intro">De CIPP-koppeling is pas te testen met een echte tenant erbij.</p>
    <div class="card pad">
      <form method="get" style="display:flex;gap:8px;flex-wrap:wrap">
        <input type="text" name="tenant" value="<?= h($tenant) ?>" placeholder="klant.onmicrosoft.com" style="max-width:320px">
        <button class="knop primair" type="submit">Test</button>
      </form>
    </div>
  </section>
</div>
</body>
</html>
