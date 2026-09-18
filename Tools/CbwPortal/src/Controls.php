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
     * @return array<string, array{naam: string, controles: array<string, array{tekst: string, kern: bool, meetbaar: bool}}>>
     */
    public static function themas(): array
    {
        return [
            'a' => ['naam' => 'Risicoanalyse en beveiligingsbeleid', 'controles' => [
                'a1' => ['tekst' => 'Vastgesteld informatiebeveiligingsbeleid, goedgekeurd door het bestuur en gedateerd', 'kern' => true,  'meetbaar' => false],
                'a2' => ['tekst' => 'Actuele risicoanalyse, minimaal jaarlijks herzien, met eigenaren per risico',        'kern' => true,  'meetbaar' => false],
                'a3' => ['tekst' => 'Vastgelegde scope: welke diensten, systemen en locaties vallen onder de Cbw',        'kern' => false, 'meetbaar' => false],
                'a4' => ['tekst' => 'Actuele inventarisatie van tenants, servers, endpoints en SaaS-diensten',            'kern' => false, 'meetbaar' => true],
            ]],
            'b' => ['naam' => 'Incidentbehandeling', 'controles' => [
                'b1' => ['tekst' => 'Incidentresponsplan met rollen, escalatiepaden en bereikbaarheid buiten kantooruren', 'kern' => true,  'meetbaar' => false],
                'b2' => ['tekst' => 'Detectie en alertering belegd en ook buiten kantooruren opgevolgd',                   'kern' => true,  'meetbaar' => false],
                'b3' => ['tekst' => 'Incidenten in een logboek, inclusief tijdstip van ontdekking (start van de 24-uursklok)', 'kern' => false, 'meetbaar' => false],
                'b4' => ['tekst' => 'Het plan is minimaal jaarlijks geoefend, met een schriftelijke terugblik',            'kern' => false, 'meetbaar' => false],
                'b5' => ['tekst' => 'Auditlogging aan, met een bewaartermijn die een incident overleeft',                  'kern' => true,  'meetbaar' => true],
            ]],
            'c' => ['naam' => 'Bedrijfscontinuiteit, back-ups en crisisbeheer', 'controles' => [
                'c1' => ['tekst' => 'Back-ups van de Microsoft 365-data buiten de tenant',                                 'kern' => true,  'meetbaar' => false],
                'c2' => ['tekst' => 'Herstel aantoonbaar getest, met datum en uitkomst van de laatste restoretest',        'kern' => true,  'meetbaar' => false],
                'c3' => ['tekst' => 'Continuiteits- en herstelplan met een RTO en RPO per kritieke dienst',                'kern' => false, 'meetbaar' => false],
                'c4' => ['tekst' => 'Crisisteam met vaste rollen en een bereikbaarheidsregeling',                          'kern' => false, 'meetbaar' => false],
            ]],
            'd' => ['naam' => 'Beveiliging van de toeleveringsketen', 'controles' => [
                'd1' => ['tekst' => 'Leveranciersregister met kritikaliteit en de toegang die elke leverancier heeft',     'kern' => true,  'meetbaar' => false],
                'd2' => ['tekst' => 'Beveiligingseisen in contracten en verwerkersovereenkomsten',                         'kern' => false, 'meetbaar' => false],
                'd3' => ['tekst' => 'Leveranciers periodiek beoordeeld op beveiliging',                                    'kern' => false, 'meetbaar' => false],
                'd4' => ['tekst' => 'Leveranciers contractueel verplicht incidenten binnen 24 uur te melden',              'kern' => true,  'meetbaar' => false],
                'd5' => ['tekst' => 'Beheerderstoegang van leveranciers via tijdelijke, herleidbare accounts',             'kern' => false, 'meetbaar' => false],
            ]],
            'e' => ['naam' => 'Verwerving, ontwikkeling en onderhoud, inclusief kwetsbaarhedenbeheer', 'controles' => [
                'e1' => ['tekst' => 'Patchbeleid met termijnen per risicoklasse, en de naleving wordt gemeten',            'kern' => true,  'meetbaar' => true],
                'e2' => ['tekst' => 'Extern benaderbare systemen periodiek gescand op kwetsbaarheden',                     'kern' => true,  'meetbaar' => false],
                'e3' => ['tekst' => 'Gepubliceerd beleid voor gecoordineerde kwetsbaarheidsmelding, met meldadres',        'kern' => false, 'meetbaar' => false],
                'e4' => ['tekst' => 'Hardening-baseline vastgesteld en afwijkingen gemeten',                               'kern' => false, 'meetbaar' => true],
                'e5' => ['tekst' => 'Nieuwe software en leveranciers voor ingebruikname beoordeeld',                       'kern' => false, 'meetbaar' => false],
            ]],
            'f' => ['naam' => 'Beoordelen of de maatregelen werken', 'controles' => [
                'f1' => ['tekst' => 'Minimaal jaarlijks een interne audit of self-assessment op de zorgplicht',            'kern' => false, 'meetbaar' => false],
                'f2' => ['tekst' => 'Meetbare indicatoren: MFA-dekking, patchachterstand, back-upsucces, phishingscore',   'kern' => false, 'meetbaar' => true],
                'f3' => ['tekst' => 'Bestuur bespreekt de uitkomsten en legt besluiten en acties vast',                    'kern' => true,  'meetbaar' => false],
                'f4' => ['tekst' => 'Kritieke diensten getest met een pentest, met opvolging van de bevindingen',          'kern' => false, 'meetbaar' => false],
            ]],
            'g' => ['naam' => 'Cyberhygiene en opleiding', 'controles' => [
                'g1' => ['tekst' => 'Bestuurders volgen aantoonbaar scholing over cyberrisico\'s',                         'kern' => true,  'meetbaar' => false],
                'g2' => ['tekst' => 'Alle medewerkers krijgen jaarlijks bewustwordingstraining, met deelnameregistratie',  'kern' => true,  'meetbaar' => false],
                'g3' => ['tekst' => 'Phishingsimulaties met opvolging van de resultaten',                                  'kern' => false, 'meetbaar' => false],
                'g4' => ['tekst' => 'Beleid voor thuiswerken, eigen apparatuur en prive-accounts voor werk',               'kern' => false, 'meetbaar' => false],
            ]],
            'h' => ['naam' => 'Cryptografie en versleuteling', 'controles' => [
                'h1' => ['tekst' => 'Vastgelegd beleid over welke versleuteling waar wordt toegepast',                     'kern' => false, 'meetbaar' => false],
                'h2' => ['tekst' => 'Alle laptops en werkstations versleuteld, centraal aantoonbaar',                      'kern' => true,  'meetbaar' => true],
                'h3' => ['tekst' => 'Verouderde protocollen uit, TLS afgedwongen op mail en webdiensten',                  'kern' => false, 'meetbaar' => false],
                'h4' => ['tekst' => 'Sleutel- en herstelsleutelbeheer belegd, inclusief wie erbij kan',                    'kern' => false, 'meetbaar' => false],
            ]],
            'i' => ['naam' => 'Personeel, toegangsbeleid en beheer van bedrijfsmiddelen', 'controles' => [
                'i1' => ['tekst' => 'Bij uitdiensttreding vervallen accounts en sessies dezelfde dag',                     'kern' => true,  'meetbaar' => true],
                'i2' => ['tekst' => 'Aantal permanente beheerdersaccounts bekend en beperkt; beheer met aparte accounts',  'kern' => true,  'meetbaar' => true],
                'i3' => ['tekst' => 'Toegangsrechten minimaal halfjaarlijks doorgelicht',                                  'kern' => false, 'meetbaar' => true],
                'i4' => ['tekst' => 'Screening voor kritieke functies',                                                    'kern' => false, 'meetbaar' => false],
                'i5' => ['tekst' => 'Gast- en gedeelde accounts geinventariseerd en voorzien van een eigenaar',            'kern' => false, 'meetbaar' => true],
            ]],
            'j' => ['naam' => 'Meervoudige authenticatie en beveiligde communicatie', 'controles' => [
                'j1' => ['tekst' => 'Alle gebruikers gebruiken MFA, bij voorkeur phishingbestendig',                       'kern' => true,  'meetbaar' => true],
                'j2' => ['tekst' => 'MFA verplicht voor alle beheerdersaccounts, zonder uitzonderingen',                   'kern' => true,  'meetbaar' => true],
                'j3' => ['tekst' => 'Verouderde authenticatie geblokkeerd en geverifieerd in de aanmeldlogboeken',         'kern' => true,  'meetbaar' => true],
                'j4' => ['tekst' => 'Beveiligd noodcommunicatiekanaal dat werkt als de eigen omgeving plat ligt',          'kern' => false, 'meetbaar' => false],
                'j5' => ['tekst' => 'Break-glass-accounts bestaan, zijn uitgezonderd van blokkerend beleid en bewaakt',    'kern' => false, 'meetbaar' => true],
            ]],
        ];
    }

    /** @return array<string, array{tekst: string, kern: bool, meetbaar: bool, thema: string, letter: string}> */
    public static function plat(): array
    {
        $plat = [];
        foreach (self::themas() as $letter => $thema) {
            foreach ($thema['controles'] as $id => $controle) {
                $plat[$id] = $controle + ['thema' => $thema['naam'], 'letter' => $letter];
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
