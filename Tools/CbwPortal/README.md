# Cbw-portaal

Een klantportaal dat aan HostBill hangt en per klant laat zien **hoe ver ze zijn** en **wat ze nog
moeten regelen** om aan de Cyberbeveiligingswet te voldoen.

De klant logt in bij HostBill, klikt op het menu-item en ziet zijn eigen dossier: een percentage,
de openstaande punten op volgorde van urgentie, en de volledige check van de zorgplicht. Wat uit
zijn Microsoft 365-omgeving te meten valt, staat er al ingevuld — met het bewijs en de meetdatum
erbij.

```
HostBill ──ondertekende link──▶ Portaal ──ListCbwReadiness──▶ CIPP ──Graph──▶ tenant
  klant                         stand +  ──seats / back-upjobs──▶ Datto of NinjaOne
  klantnummer                   antwoorden
```

## Wat het toont

| | |
| --- | --- |
| **Waar u staat** | Percentage geregeld, aantal openstaande kernpunten, totaal open, aantal automatisch gemeten controles |
| **Wat u nog moet regelen** | Alles wat op *deels* of *niet* staat, kernpunten eerst — dit is de lijst waar de klant mee aan de slag gaat |
| **De volledige check** | De tien maatregelen van artikel 21 lid 2 NIS2, uitgewerkt in 45 controles, met per controle de meting en een statusknop |
| **Rapport downloaden** | De volledige stand als pdf (via printen) of als json, met de meetdatum erbij — `rapport.php` |

Van de 45 controles worden er **16 automatisch uitgelezen**, waaronder 10 van de 20 kernpunten.
`demo.php` toont die lijst openbaar en zonder klantgegevens: de etalage voor een prospect.

De klant kan zelf statussen zetten en notities vastleggen. Twee regels dragen het hele model:

1. **Een handmatig antwoord wint altijd van een meting.** Iemand die weet dat de back-up niet
   getest is, weet meer dan een API. Wijkt het antwoord af van de meting, dan staat dat erbij.
2. **Een meting die niet lukte is geen geslaagde controle.** Een bevinding `onbekend` telt als
   onbeantwoord, nooit als groen. Mislukt de nachtelijke meting helemaal, dan blijft de vorige
   stand staan met de datum erbij — nooit een leeg scherm dat als "in orde" leest.

## Onderdelen

```
src/Controls.php    het controlemodel: 10 thema's, 45 controles (zelfde ids als CIPP en de wegwijzer)
                    plus bronnen(): de enige plek die vastlegt wat automatisch wordt gevuld
src/HostBill.php    Admin API-client (getClients, getClientDetails)
src/Cipp.php        Entra client credentials + ListCbwReadiness
src/Backup/         back-upbronnen: NinjaOne en Datto SaaS Protection, achter één interface
src/Dossier.php     opslag per klant: koppeling, antwoorden, laatste meting
src/Stand.php       samenvoegen van meting en antwoorden tot één beeld
src/Link.php        ondertekende klantlinks (HMAC-SHA256)
public/index.php    klantweergave
public/admin.php    beheer: klanten, koppelingen, standen, klantlinks
public/rapport.php  het rapport dat de klant downloadt (pdf via printen, of json)
public/demo.php     openbare etalage: wat wij uitlezen, met voorbeelden
public/diagnose.php verbindingstest die zegt wat er misgaat en waar je het oplost
bin/sync.php        nachtelijke meting (cron)
hostbill/ga-naar-portaal.php   de brug vanuit HostBill
```

Geen composer, geen framework: PHP 8.1 of nieuwer met `pdo_sqlite` en `curl`. De opslag is SQLite;
`db` mag ook een MySQL-DSN zijn.

## Installeren

**1. Neerzetten.** Kopieer de map naar de server. Laat alleen `public/` door de webserver
serveren — `src/`, `data/` en `config.php` horen daarbuiten te staan.

**2. Instellen.**

```bash
cp config.voorbeeld.php config.php
php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"   # geheim voor link_secret
```

Vul in `config.php`: de HostBill-URL met API-id en -sleutel, de CIPP-gegevens, `link_secret`,
`admin_wachtwoord` en `portaal_url`.

**3. HostBill.** Maak onder *Settings → Security → API access* een sleutel aan en geef die alleen
`getClients` en `getClientDetails` — niets meer. Wilt u de tenant automatisch overnemen, maak dan
een custom field bij de klant (standaard heet het `Microsoft tenant`) en vul daar de tenantnaam in.

**4. Back-up.** Zet `backup_bron` op `datto` of `ninjaone`.

- **Datto SaaS Protection** — maak een API-sleutel in het Partner Portal onder *Admin → Integrations →
  Create API Key*. `backup_id` en `backup_secret` zijn de publieke en geheime sleutel; `backup_url` is
  doorgaans `https://api.datto.com`. Het portaal leest `/v1/saas/domains` en
  `/v1/saas/{saasCustomerId}/seats`.
- **NinjaOne** — maak onder *Administration → Apps → API* een machine-to-machine client met scope
  `monitoring` (alleen lezen). `backup_url` is uw regio, bijvoorbeeld `https://eu.ninjarmm.com`. Het
  portaal leest `/v2/organizations`, `/v2/backup/jobs` en `/v2/backup/integrity-check-jobs`.

Vul daarna per klant het organisatie-id in de kolom *Back-up* in het beheerscherm. Dat vult controle
**c1** (back-up buiten de tenant). Voor **c2** geldt een grens die we niet oprekken: NinjaOne's
integriteitscontroles leveren hoogstens *deels*, want ze tonen dat een back-up leesbaar is — niet dat
er een herstelproef is gedaan en beschreven. Datto levert voor c2 niets; seat-status bewijst dat er
data ligt, niet dat er ooit iets uit is teruggezet.

**5. CIPP.** Maak onder *Settings → API access* een API-client met de rol `Tenant.Reports.Read`.
Noteer de application id en het secret. Het portaal haalt daarmee een token bij Entra ID met scope
`api://<client id>/.default` en roept `ListCbwReadiness` aan — het endpoint uit deze repo dat een
tenant afzet tegen de zorgplicht.

**6. De brug.** Zet `hostbill/ga-naar-portaal.php` in de webroot van HostBill, vul `PORTAAL_URL` en
`GEDEELD_GEHEIM` in (hetzelfde geheim als `link_secret`) en maak in het klantenpaneel een menu-item
dat ernaar wijst.

**7. Cron.**

```cron
20 3 * * * php /pad/naar/CbwPortal/bin/sync.php >> /var/log/cbw-sync.log 2>&1
```

**8. Controleren.** Log in op `admin.php`, klik *Klanten uit HostBill ophalen*, koppel de tenants
en klik *Meet*. `diagnose.php` test elke verbinding apart en zegt per fout waar je hem oplost.

## Hoe de toegang werkt

Het portaal kent de sessie van HostBill niet. `ga-naar-portaal.php` draait bínnen HostBill, leest
daar het klantnummer uit de sessie en ondertekent een link met het gedeelde geheim:

```
index.php?t=<klantnummer>.<vervaltijd>.<HMAC-SHA256>
```

Het portaal controleert de handtekening en de vervaltijd. Zonder het geheim is zo'n link niet te
maken en niet om te schrijven naar een ander klantnummer. De link uit HostBill is twaalf uur
geldig; een link die u vanuit het beheerscherm kopieert, een maand.

Dit is ook het enige bestand dat iets van HostBill van binnen aanraakt. De sleutel waarmee
HostBill het klantnummer in de sessie zet, verschilt per versie: het bestand probeert de bekende
varianten en zegt het met zoveel woorden als geen ervan past, in plaats van een gok te doen — een
verkeerd klantnummer zou de ene klant het dossier van de andere laten zien.

## Wat CIPP wel en niet kan meten

Gemeten: MFA-dekking van gebruikers en beheerders, phishingbestendige methoden, blokkade van
verouderde authenticatie, uitzonderingen op voorwaardelijke toegang, permanente global admins,
schijfversleuteling, apparaatnaleving, slapende gelicentieerde accounts, gasten,
toegangsbeoordelingen, het uniforme auditlogboek, toegepaste CIPP-standaarden en Secure Score.

Uit de back-upbron: of er buiten de tenant een actuele kopie ligt, en of die is geverifieerd.

Niet te meten, en dus altijd handwerk: de herstelproef zelf, leveranciersafspraken, CVD-beleid,
bestuursscholing, het incidentresponsplan en noodcommunicatie. Die komen als zodanig in beeld, met
de reden erbij.

## Grenzen

Een hulpmiddel om samen bij te houden waar een klant staat — geen juridisch advies en geen formele
toets aan de Cyberbeveiligingswet. Een meting toont wat op dat moment aantoonbaar was in de
tenant, niet of een maatregel ook werkt zoals bedoeld.
