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
