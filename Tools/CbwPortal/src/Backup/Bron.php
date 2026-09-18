<?php
declare(strict_types=1);

namespace CbwPortal\Backup;

/**
 * Een bron die kan aantonen dat er back-ups draaien buiten de productieomgeving.
 *
 * Levert bevindingen in dezelfde vorm als CIPP, zodat het portaal ze op precies dezelfde manier
 * behandelt: c1 (back-ups buiten de tenant) en c2 (herstel aantoonbaar getest).
 *
 * De regel die overal geldt, geldt hier het hardst: een bron die niets teruggeeft levert
 * 'onbekend', nooit 'geregeld'. Een back-up waarvan wij het bestaan niet kunnen vaststellen, is
 * voor de zorgplicht geen back-up.
 */
interface Bron
{
    /**
     * @param string $referentie De sleutel van deze klant bij de bron: een NinjaOne-organisatie-id
     *                           of een Datto saasCustomerId.
     * @return array<string, array{status: string, kop: string, detail: string, bron: string}>
     */
    public function bevindingen(string $referentie): array;

    /** @return array<int, array{id: string, naam: string}> Alles wat de bron kent, om aan klanten te koppelen. */
    public function organisaties(): array;

    public function naam(): string;

    /** @return array{ok: bool, bericht: string} */
    public function test(): array;
}
