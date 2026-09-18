# Cbw-wegwijzer

Een zelfstandige webapp waarmee je een klant stap voor stap door de Nederlandse
**Cyberbeveiligingswet** (Cbw, de implementatie van NIS2) heen loodst: valt de
klant eronder, wat moet er geregeld zijn, en wat staat er nog open.

De wet is op **15 augustus 2026** in werking getreden. Er is geen gedoog- of
overgangsperiode: registratieplicht, zorgplicht en meldplicht gelden sinds die
datum onverkort.

## Wat het doet

| Stap | Inhoud |
| --- | --- |
| 00 | Dossiergegevens: organisatie, verantwoordelijke, peildatum |
| 01 | Scopebepaling — 18 sectoren, omvangsdrempels en bijzondere gevallen → essentiële entiteit, belangrijke entiteit of buiten scope, met de indicatieve toezichthouder |
| 02 | De vier verplichtingen: registratie, zorgplicht, meldplicht en bestuurlijke verantwoordelijkheid |
| 03 | Zorgplicht-check: de tien maatregelen uit artikel 21 lid 2 NIS2 (sub a t/m j), vertaald naar 40 controles die in een Microsoft 365-omgeving aantoonbaar zijn |
| 04 | Actielijst: alles wat op *deels* of *niet* staat, kernpunten eerst — printbaar als klantrapport |
| 05 | Meldplicht-draaiboek: de tijdlijn 24 uur → 72 uur → eindverslag binnen een maand |

Controles die een toezichthouder als eerste opvraagt zijn gemarkeerd als
**kern**. Waar een controle in Microsoft 365 aantoonbaar is, staat erbij waar je
het bewijs vandaan haalt (Intune, Entra, Defender, Purview, CIPP).

## Koppeling met CIPP

Stap 03 kan zichzelf vullen uit een echte tenant. Het endpoint
`GET /api/ListCbwReadiness?tenantFilter=<tenant>` (rol `Tenant.Reports.Read`) leest de tenant uit en
geeft per controle een oordeel terug met het bewijs erbij:

```jsonc
{
  "TenantFilter": "klant.onmicrosoft.com",
  "GeneratedAt":  "2026-09-14T09:12:44.0000000Z",
  "Controls": [
    { "ControlId": "j2", "Article": "art. 21.2 j", "Status": "geregeld",
      "Headline": "6 van 6 beheerders (100%) kan MFA gebruiken",
      "Source": "Entra ID - userRegistrationDetails",
      "Metric": { "Value": 6, "Total": 6, "Percentage": 100 } }
  ],
  "NotDetectable": [
    { "ControlId": "c1", "Reason": "Of er back-ups buiten de tenant staan, is niet uit Microsoft 365 af te leiden." }
  ]
}
```

Wat het uitleest: MFA-dekking van gebruikers en beheerders, phishingbestendige methoden, blokkade van
verouderde authenticatie, uitzonderingen op voorwaardelijke toegang, aantal permanente global admins,
schijfversleuteling, apparaatnaleving, slapende gelicentieerde accounts, gastaccounts,
toegangsbeoordelingen, het uniforme auditlogboek, toegepaste CIPP-standaarden en Secure Score.

Wat het niet uitleest, en ook niet vóórinvult: back-ups buiten de tenant, restoretests,
leveranciersafspraken, CVD-beleid, bestuursscholing en noodcommunicatie. Die komen terug onder
`NotDetectable` met de reden erbij, zodat een ontbrekend signaal nooit als een geslaagde controle leest.

Twee routes vanaf de webapp:

1. **Rechtstreeks ophalen** — vul de basis-URL van CIPP en de tenant in en klik *Stand ophalen*. Dit
   werkt zodra de pagina op een domein draait dat CIPP in zijn CORS-instellingen toestaat en waar de
   gebruiker is ingelogd. Vanaf een gepubliceerd artifact op `claude.ai` is dat standaard níet zo.
2. **Rapport importeren** — roep het endpoint in CIPP aan, bewaar het antwoord als JSON en klik
   *Rapport importeren*. Werkt altijd, ongeacht domein.

Een handmatig antwoord wint altijd van een bevinding uit CIPP; de app markeert het dan als *handmatig
overschreven*. De app slaat geen tokens of inloggegevens op — alleen de basis-URL en de tenantnaam.

## Buiten scope is geen leeg scherm

Valt een klant niet onder de wet, dan blijft de hele check staan en verandert alleen de framing: de
actielijst wordt een nulmeting op volgorde van risico in plaats van urgentie. Dat is precies het
antwoord op de leveranciersvragenlijsten die klanten die er wél onder vallen gaan versturen — hun
ketenverplichting (maatregel `d`) wordt andermans huiswerk.

## Het uitdeelbare stappenplan

`stappenplan.html` is de begeleidende uitgave voor klanten: dertien A4-pagina's die in zes stappen
door de wet lopen, van scope tot jaarcyclus, met een checklist en een planning van negentig dagen.
Bedoeld om te printen, mee te sturen of als download achter een formulier te zetten.

Het merk zit op twee plekken, allebei bovenin het bestand:

```js
const MERK = {
  naam:   "Uw organisatie",
  accent: "#1f4a8f",   // hoofdkleur
  diep:   "#16345f"    // donkere variant voor omslag en slotkader
};
```

Naam en kleuren werken door in elke pagina, de omslag en het slotkader. Wilt u een logo op de
omslag, vervang dan het element met de klasse `merk` in de eerste `section` door een `<img>`.

De pdf maakt u met:

```bash
npm i playwright
node maak-pdf.mjs      # -> Stappenplan-Cyberbeveiligingswet.pdf
```

Printen vanuit de browser kan ook: kies A4, marges "standaard" en zet achtergrondafbeeldingen aan.
De lettertypen zijn als data-uri in het bestand opgenomen, dus de opmaak klopt ook zonder netwerk.
De paginaindeling is krap afgesteld: als u tekst toevoegt, controleer dan of het nog dertien
pagina's zijn.

## Draaien

Eén bestand, geen build en geen afhankelijkheden:

```bash
# lokaal
xdg-open index.html

# of serveren
python3 -m http.server 8080
```

## Opslag

De app kiest automatisch de beste opslag die beschikbaar is:

1. **Gepubliceerd als Claude-artifact** — gedeeld dossier via de `db`-capability.
   Iedereen met de link ziet en bewerkt dezelfde stand, live. Eén link per klant:
   deel hem dus niet met een andere klant.
2. **Overal elders** (lokaal bestand, eigen webserver) — `localStorage` in de
   browser van de gebruiker.

In beide gevallen kun je het dossier als JSON exporteren en importeren, zodat je
een ingevulde stand kunt overdragen of archiveren.

## Grenzen

Een hulpmiddel om het gesprek te structureren, geen juridisch advies en geen
formele toets. De uitkomst van stap 01 is een indicatie: een aanwijzing door een
minister, de positie van enige aanbieder van een dienst, of een sectorale *lex
specialis* (zoals DORA voor de financiële sector) kan anders uitpakken. De
toezichthouder per sector is indicatief opgenomen en moet bij aanmelding worden
bevestigd.

Bronnen: [NCSC](https://www.ncsc.nl/cyberbeveiligingswet-nis2),
[NCTV](https://www.nctv.nl/onderwerpen/c/cyberbeveiligingswet),
[RDI](https://www.rdi.nl/onderwerpen/cyberveiligheid/cyberbeveiligingswet/meldplicht),
[Digitale Overheid](https://www.digitaleoverheid.nl/overzicht-van-alle-onderwerpen/cyberbeveiligingswet/verplichtingen-cyberbeveiligingswet/).
