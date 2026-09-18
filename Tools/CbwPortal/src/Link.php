<?php
declare(strict_types=1);

namespace CbwPortal;

/**
 * Ondertekende klantlinks.
 *
 * Het portaal hoeft de sessie van HostBill niet te kennen: de HostBill-module maakt een link met
 * het klantnummer, een vervaltijd en een HMAC-handtekening. Het portaal controleert de
 * handtekening en weet dan zeker dat HostBill de bezoeker heeft geïdentificeerd.
 *
 * Het geheim is gedeeld tussen de HostBill-module en dit portaal en staat in beide configuraties.
 * Zonder dat geheim is een link niet te vervalsen en niet te hergebruiken voor een andere klant.
 */
final class Link
{
    public function __construct(
        private string $secret,
        private int $geldigheid = 2592000,
    ) {
    }

    public function maak(string $clientId, ?int $verlooptOp = null): string
    {
        $verlooptOp ??= time() + $this->geldigheid;
        $nuttig = $clientId . '.' . $verlooptOp;

        return $nuttig . '.' . $this->handtekening($nuttig);
    }

    /** Geeft het klantnummer terug, of null als het token niet klopt of verlopen is. */
    public function controleer(string $token): ?string
    {
        $delen = explode('.', $token);
        if (count($delen) !== 3) {
            return null;
        }

        [$clientId, $verlooptOp, $handtekening] = $delen;
        $nuttig = $clientId . '.' . $verlooptOp;

        if (!hash_equals($this->handtekening($nuttig), $handtekening)) {
            return null;
        }
        if (!ctype_digit($verlooptOp) || (int)$verlooptOp < time()) {
            return null;
        }

        return $clientId;
    }

    public function url(string $basis, string $clientId): string
    {
        return rtrim($basis, '/') . '/index.php?t=' . rawurlencode($this->maak($clientId));
    }

    private function handtekening(string $nuttig): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $nuttig, $this->secret, true)), '+/', '-_'), '=');
    }
}
