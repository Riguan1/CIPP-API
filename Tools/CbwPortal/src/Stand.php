<?php
declare(strict_types=1);

namespace CbwPortal;

/**
 * Voegt de automatische bevindingen uit CIPP samen met de handmatige antwoorden tot één beeld:
 * hoe ver is deze klant, en wat moet er nog gebeuren.
 *
 * Twee regels die het hele model dragen:
 *   1. Een handmatig antwoord wint altijd van een bevinding. Een mens die zegt dat iets niet
 *      geregeld is, weet meer dan een meting.
 *   2. Een bevinding 'onbekend' is geen antwoord. Een controle die niet gemeten kon worden telt
 *      als onbeantwoord, nooit als geslaagd - anders vertelt het portaal de klant dat hij
 *      compliant is omdat een API het even niet deed.
 */
final class Stand
{
    /** @param array<string, array> $bevindingen @param array<string, array> $antwoorden */
    public function __construct(
        private array $bevindingen,
        private array $nietTeMeten,
        private array $antwoorden,
    ) {
    }

    public static function voor(Dossier $dossier, string $clientId): self
    {
        $opgeslagen = $dossier->stand($clientId);
        $stand = $opgeslagen['stand'] ?? [];

        return new self(
            $stand['bevindingen'] ?? [],
            $stand['nietTeMeten'] ?? [],
            $dossier->antwoorden($clientId),
        );
    }

    public function effectief(string $controle): ?string
    {
        $handmatig = $this->antwoorden[$controle]['status'] ?? null;
        if ($handmatig !== null && $handmatig !== '') {
            return $handmatig;
        }

        $auto = $this->bevindingen[$controle]['status'] ?? null;
        return ($auto !== null && $auto !== 'onbekend') ? $auto : null;
    }

    public function bevinding(string $controle): ?array
    {
        return $this->bevindingen[$controle] ?? null;
    }

    public function nietMeetbaar(string $controle): ?string
    {
        return $this->nietTeMeten[$controle] ?? null;
    }

    public function antwoord(string $controle): array
    {
        return $this->antwoorden[$controle] ?? ['status' => null, 'notitie' => null, 'door' => null, 'bijgewerkt' => null];
    }

    public function overschreven(string $controle): bool
    {
        $handmatig = $this->antwoorden[$controle]['status'] ?? null;
        $auto = $this->bevindingen[$controle]['status'] ?? null;

        return $handmatig !== null && $handmatig !== ''
            && $auto !== null && $auto !== 'onbekend'
            && $handmatig !== $auto;
    }

    /** Percentage geregeld over alles wat van toepassing is. */
    public function percentage(): int
    {
        [$som, $telt] = $this->tel(array_keys(Controls::plat()));
        return $telt > 0 ? (int)round(($som / $telt) * 100) : 0;
    }

    public function percentageThema(string $letter): int
    {
        $ids = array_keys(Controls::themas()[$letter]['controles'] ?? []);
        [$som, $telt] = $this->tel($ids);
        return $telt > 0 ? (int)round(($som / $telt) * 100) : 0;
    }

    /** @param array<int, string> $ids @return array{0: float, 1: int} */
    private function tel(array $ids): array
    {
        $som = 0.0;
        $telt = 0;

        foreach ($ids as $id) {
            $status = $this->effectief($id);
            if ($status === 'nvt') {
                continue;
            }
            $telt++;
            $som += Controls::WEGING[$status] ?? 0.0;
        }

        return [$som, $telt];
    }

    /**
     * Alles wat nog moet gebeuren, kernpunten eerst, daarbinnen 'niet geregeld' voor 'deels'.
     *
     * @return array<int, array{id: string, tekst: string, letter: string, status: string, kern: bool, toelichting: string}>
     */
    public function openstaand(): array
    {
        $items = [];

        foreach (Controls::plat() as $id => $controle) {
            $status = $this->effectief($id);
            if ($status === 'geregeld' || $status === 'nvt') {
                continue;
            }

            $notitie = $this->antwoorden[$id]['notitie'] ?? null;
            $bevinding = $this->bevindingen[$id] ?? null;
            $niet = $this->nietTeMeten[$id] ?? null;

            if ($notitie) {
                $toelichting = $notitie;
            } elseif ($bevinding && ($bevinding['status'] ?? '') !== 'onbekend') {
                $toelichting = 'Gemeten: ' . $bevinding['kop'];
            } elseif ($niet) {
                $toelichting = $niet;
            } else {
                $toelichting = $controle['thema'];
            }

            $items[] = [
                'id'          => $id,
                'tekst'       => $controle['tekst'],
                'letter'      => $controle['letter'],
                'status'      => $status ?? 'open',
                'kern'        => $controle['kern'],
                'toelichting' => $toelichting,
            ];
        }

        usort($items, static function (array $a, array $b): int {
            $rang = static fn(array $i): int => ($i['kern'] ? 0 : 2) + ($i['status'] === 'open' ? 0 : 1);
            return $rang($a) <=> $rang($b) ?: strcmp($a['id'], $b['id']);
        });

        return $items;
    }

    /** @return array{totaal: int, beantwoord: int, gemeten: int, open: int, kern_open: int, nvt: int} */
    public function samenvatting(): array
    {
        $totaal = Controls::aantal();
        $beantwoord = 0;
        $open = 0;
        $kernOpen = 0;
        $nvt = 0;

        foreach (Controls::plat() as $id => $controle) {
            $status = $this->effectief($id);
            if ($status === 'nvt') {
                $nvt++;
                continue;
            }
            if ($status !== null) {
                $beantwoord++;
            }
            if ($status !== 'geregeld') {
                $open++;
                if ($controle['kern']) {
                    $kernOpen++;
                }
            }
        }

        $gemeten = count(array_filter(
            $this->bevindingen,
            static fn(array $b) => ($b['status'] ?? 'onbekend') !== 'onbekend',
        ));

        return [
            'totaal' => $totaal, 'beantwoord' => $beantwoord, 'gemeten' => $gemeten,
            'open' => $open, 'kern_open' => $kernOpen, 'nvt' => $nvt,
        ];
    }
}
