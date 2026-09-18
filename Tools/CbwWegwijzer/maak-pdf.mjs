// Rendert stappenplan.html naar een pdf van 13 A4-pagina's.
//   npm i playwright && node maak-pdf.mjs
// De lettertypen zitten in het html-bestand, dus dit werkt ook zonder netwerk.
import { chromium } from 'playwright';

const bron = new URL('./stappenplan.html', import.meta.url).href;
const doel = 'Stappenplan-Cyberbeveiligingswet.pdf';

const browser = await chromium.launch();
const pagina = await browser.newPage();
await pagina.goto(bron, { waitUntil: 'networkidle' });
await pagina.emulateMedia({ media: 'print' });
await pagina.pdf({ path: doel, format: 'A4', printBackground: true, preferCSSPageSize: true });
await browser.close();

console.log(`Geschreven: ${doel}`);
