<?php
declare(strict_types=1);

namespace CbwPortal;

/**
 * Het controlemodel van de zorgplicht: de tien maatregelen van artikel 21 lid 2 NIS2,
 * uitgewerkt in vijfenveertig controles.
 *
 * De identifiers zijn dezelfde als in Tools/CbwWegwijzer en als die welke
 * ListCbwReadiness in CIPP teruggeeft. Wie hier een controle toevoegt, voegt hem
 * daar ook toe - anders komt een bevinding binnen die nergens landt.
 */
final class Controls
{
    /** Gewicht van een status in de voortgangsberekening. 'nvt' telt niet mee. */
    public const WEGING = ['geregeld' => 1.0, 'deels' => 0.5, 'open' => 0.0];

    public const STATUSSEN = ['geregeld', 'deels', 'open', 'nvt'];

    /**
     * @return array<string, array{naam: string, controles: array<string, array{tekst: string, kern: bool}}>>
     */
    public static function themas(): array
    {
        return [
            'a' => ['naam' => 'Risicoanalyse en beveiligingsbeleid', 'controles' => [
                'a1' => ['tekst' => 'Vastgesteld informatiebeveiligingsbeleid, goedgekeurd door het bestuur en gedateerd', 'kern' => true],
                'a2' => ['tekst' => 'Actuele risicoanalyse, minimaal jaarlijks herzien, met eigenaren per risico',        'kern' => true],
                'a3' => ['tekst' => 'Vastgelegde scope: welke diensten, systemen en locaties vallen onder de Cbw',        'kern' => false],
                'a4' => ['tekst' => 'Actuele inventarisatie van tenants, servers, endpoints en SaaS-diensten',            'kern' => false],
            ]],
            'b' => ['naam' => 'Incidentbehandeling', 'controles' => [
                'b1' => ['tekst' => 'Incidentresponsplan met rollen, escalatiepaden en bereikbaarheid buiten kantooruren', 'kern' => true],
                'b2' => ['tekst' => 'Detectie en alertering belegd en ook buiten kantooruren opgevolgd',                   'kern' => true],
                'b3' => ['tekst' => 'Incidenten in een logboek, inclusief tijdstip van ontdekking (start van de 24-uursklok)', 'kern' => false],
                'b4' => ['tekst' => 'Het plan is minimaal jaarlijks geoefend, met een schriftelijke terugblik',            'kern' => false],
                'b5' => ['tekst' => 'Auditlogging aan, met een bewaartermijn die een incident overleeft',                  'kern' => true],
            ]],
            'c' => ['naam' => 'Bedrijfscontinuiteit, back-ups en crisisbeheer', 'controles' => [
                'c1' => ['tekst' => 'Back-ups van de Microsoft 365-data buiten de tenant',                                 'kern' => true],
                'c2' => ['tekst' => 'Herstel aantoonbaar getest, met datum en uitkomst van de laatste restoretest',        'kern' => true],
                'c3' => ['tekst' => 'Continuiteits- en herstelplan met een RTO en RPO per kritieke dienst',                'kern' => false],
                'c4' => ['tekst' => 'Crisisteam met vaste rollen en een bereikbaarheidsregeling',                          'kern' => false],
            ]],
            'd' => ['naam' => 'Beveiliging van de toeleveringsketen', 'controles' => [
                'd1' => ['tekst' => 'Leveranciersregister met kritikaliteit en de toegang die elke leverancier heeft',     'kern' => true],
                'd2' => ['tekst' => 'Beveiligingseisen in contracten en verwerkersovereenkomsten',                         'kern' => false],
                'd3' => ['tekst' => 'Leveranciers periodiek beoordeeld op beveiliging',                                    'kern' => false],
                'd4' => ['tekst' => 'Leveranciers contractueel verplicht incidenten binnen 24 uur te melden',              'kern' => true],
                'd5' => ['tekst' => 'Beheerderstoegang van leveranciers via tijdelijke, herleidbare accounts',             'kern' => false],
            ]],
            'e' => ['naam' => 'Verwerving, ontwikkeling en onderhoud, inclusief kwetsbaarhedenbeheer', 'controles' => [
                'e1' => ['tekst' => 'Patchbeleid met termijnen per risicoklasse, en de naleving wordt gemeten',            'kern' => true],
                'e2' => ['tekst' => 'Extern benaderbare systemen periodiek gescand op kwetsbaarheden',                     'kern' => true],
                'e3' => ['tekst' => 'Gepubliceerd beleid voor gecoordineerde kwetsbaarheidsmelding, met meldadres',        'kern' => false],
                'e4' => ['tekst' => 'Hardening-baseline vastgesteld en afwijkingen gemeten',                               'kern' => false],
                'e5' => ['tekst' => 'Nieuwe software en leveranciers voor ingebruikname beoordeeld',                       'kern' => false],
            ]],
            'f' => ['naam' => 'Beoordelen of de maatregelen werken', 'controles' => [
                'f1' => ['tekst' => 'Minimaal jaarlijks een interne audit of self-assessment op de zorgplicht',            'kern' => false],
                'f2' => ['tekst' => 'Meetbare indicatoren: MFA-dekking, patchachterstand, back-upsucces, phishingscore',   'kern' => false],
                'f3' => ['tekst' => 'Bestuur bespreekt de uitkomsten en legt besluiten en acties vast',                    'kern' => true],
                'f4' => ['tekst' => 'Kritieke diensten getest met een pentest, met opvolging van de bevindingen',          'kern' => false],
            ]],
            'g' => ['naam' => 'Cyberhygiene en opleiding', 'controles' => [
                'g1' => ['tekst' => 'Bestuurders volgen aantoonbaar scholing over cyberrisico\'s',                         'kern' => true],
                'g2' => ['tekst' => 'Alle medewerkers krijgen jaarlijks bewustwordingstraining, met deelnameregistratie',  'kern' => true],
                'g3' => ['tekst' => 'Phishingsimulaties met opvolging van de resultaten',                                  'kern' => false],
                'g4' => ['tekst' => 'Beleid voor thuiswerken, eigen apparatuur en prive-accounts voor werk',               'kern' => false],
            ]],
            'h' => ['naam' => 'Cryptografie en versleuteling', 'controles' => [
                'h1' => ['tekst' => 'Vastgelegd beleid over welke versleuteling waar wordt toegepast',                     'kern' => false],
                'h2' => ['tekst' => 'Alle laptops en werkstations versleuteld, centraal aantoonbaar',                      'kern' => true],
                'h3' => ['tekst' => 'Verouderde protocollen uit, TLS afgedwongen op mail en webdiensten',                  'kern' => false],
                'h4' => ['tekst' => 'Sleutel- en herstelsleutelbeheer belegd, inclusief wie erbij kan',                    'kern' => false],
            ]],
            'i' => ['naam' => 'Personeel, toegangsbeleid en beheer van bedrijfsmiddelen', 'controles' => [
                'i1' => ['tekst' => 'Bij uitdiensttreding vervallen accounts en sessies dezelfde dag',                     'kern' => true],
                'i2' => ['tekst' => 'Aantal permanente beheerdersaccounts bekend en beperkt; beheer met aparte accounts',  'kern' => true],
                'i3' => ['tekst' => 'Toegangsrechten minimaal halfjaarlijks doorgelicht',                                  'kern' => false],
                'i4' => ['tekst' => 'Screening voor kritieke functies',                                                    'kern' => false],
                'i5' => ['tekst' => 'Gast- en gedeelde accounts geinventariseerd en voorzien van een eigenaar',            'kern' => false],
            ]],
            'j' => ['naam' => 'Meervoudige authenticatie en beveiligde communicatie', 'controles' => [
                'j1' => ['tekst' => 'Alle gebruikers gebruiken MFA, bij voorkeur phishingbestendig',                       'kern' => true],
                'j2' => ['tekst' => 'MFA verplicht voor alle beheerdersaccounts, zonder uitzonderingen',                   'kern' => true],
                'j3' => ['tekst' => 'Verouderde authenticatie geblokkeerd en geverifieerd in de aanmeldlogboeken',         'kern' => true],
                'j4' => ['tekst' => 'Beveiligd noodcommunicatiekanaal dat werkt als de eigen omgeving plat ligt',          'kern' => false],
                'j5' => ['tekst' => 'Break-glass-accounts bestaan, zijn uitgezonderd van blokkerend beleid en bewaakt',    'kern' => false],
            ]],
        ];
    }

    /**
     * Waar een controle vandaan komt als hij automatisch wordt gevuld. Staat een controle hier niet
     * in, dan is hij handwerk. Dit is de enige plek waar dat wordt vastgelegd, zodat de lijst niet
     * uit de pas kan lopen met wat de koppelingen werkelijk teruggeven.
     *
     * @return array<string, string>
     */
    public static function bronnen(): array
    {
        return [
            // Uit CIPP, via ListCbwReadiness
            'a4' => 'Intune - apparaatinventaris',
            'b5' => 'Exchange Online - auditlogboek',
            'e1' => 'Intune - apparaatnaleving',
            'e4' => 'CIPP - toegepaste standaarden',
            'f2' => 'Microsoft Secure Score',
            'g3' => 'Defender for Office 365 - aanvalssimulaties',
            'h3' => 'Exchange Online - verouderde protocollen',
            'h2' => 'Intune - schijfversleuteling',
            'i1' => 'Entra ID - aanmeldactiviteit',
            'i2' => 'Entra ID - beheerdersrollen',
            'i3' => 'Entra ID - toegangsbeoordelingen',
            'i5' => 'Entra ID - gastaccounts',
            'j1' => 'Entra ID - verificatiemethoden',
            'j2' => 'Entra ID - verificatiemethoden',
            'j3' => 'Entra ID - voorwaardelijke toegang',
            'j5' => 'Entra ID - voorwaardelijke toegang',
            // Uit HostBill
            'b3' => 'HostBill - ticketregistratie',
            // Uit de back-upbron, als die is gekoppeld
            'c1' => 'Datto of NinjaOne - back-upstatus',
            'c2' => 'NinjaOne - integriteitscontroles',
        ];
    }

    /** @return array<string, array{tekst: string, kern: bool, meetbaar: bool, bron: ?string, thema: string, letter: string}> */
    public static function plat(): array
    {
        $bronnen = self::bronnen();
        $plat = [];

        foreach (self::themas() as $letter => $thema) {
            foreach ($thema['controles'] as $id => $controle) {
                $plat[$id] = $controle + [
                    'meetbaar' => isset($bronnen[$id]),
                    'bron'     => $bronnen[$id] ?? null,
                    'thema'    => $thema['naam'],
                    'letter'   => $letter,
                ];
            }
        }

        return $plat;
    }

    public static function aantal(): int
    {
        return count(self::plat());
    }

    /** De vier verplichtingen naast de zorgplicht. Deze beantwoordt de klant zelf. */
    public static function plichten(): array
    {
        return [
            'registratie' => ['titel' => 'Registratieplicht', 'termijn' => 'Geldt sinds 15 augustus 2026',
                'tekst' => 'Registreer de organisatie in het entiteitenregister via mijn.ncsc.nl.'],
            'meldplicht'  => ['titel' => 'Meldplicht', 'termijn' => '24 uur / 72 uur / 1 maand',
                'tekst' => 'Significante incidenten melden bij het CSIRT en bij de toezichthouder. Regel vooraf wie mag melden.'],
            'bestuur'     => ['titel' => 'Bestuurlijke verantwoordelijkheid', 'termijn' => 'Doorlopend',
                'tekst' => 'Het bestuur keurt de maatregelen goed, ziet toe op de uitvoering en volgt zelf scholing.'],
        ];
    }
}
