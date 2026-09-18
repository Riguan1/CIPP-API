<?php
declare(strict_types=1);

namespace CbwPortal;

use RuntimeException;

/**
 * Instellingen, uit config.php of uit omgevingsvariabelen.
 *
 * Geheimen horen niet in de code: zet ze in config.php buiten de webroot, of geef ze mee als
 * omgevingsvariabelen. config.php staat in .gitignore.
 */
final class Config
{
    private array $waarden;

    private function __construct(array $waarden)
    {
        $this->waarden = $waarden;
    }

    public static function laden(): self
    {
        $bestand = dirname(__DIR__) . '/config.php';
        $waarden = is_file($bestand) ? (array)require $bestand : [];

        // Omgevingsvariabelen winnen, zodat een container geen bestand nodig heeft.
        foreach ([
            'hostbill_url'      => 'CBW_HOSTBILL_URL',
            'hostbill_api_id'   => 'CBW_HOSTBILL_API_ID',
            'hostbill_api_key'  => 'CBW_HOSTBILL_API_KEY',
            'hostbill_veld'     => 'CBW_HOSTBILL_TENANTVELD',
            'cipp_url'          => 'CBW_CIPP_URL',
            'cipp_tenant_id'    => 'CBW_CIPP_TENANT_ID',
            'cipp_client_id'    => 'CBW_CIPP_CLIENT_ID',
            'cipp_secret'       => 'CBW_CIPP_SECRET',
            'cipp_scope'        => 'CBW_CIPP_SCOPE',
            'link_secret'       => 'CBW_LINK_SECRET',
            'admin_wachtwoord'  => 'CBW_ADMIN_WACHTWOORD',
            'backup_bron'       => 'CBW_BACKUP_BRON',
            'backup_url'        => 'CBW_BACKUP_URL',
            'backup_id'         => 'CBW_BACKUP_ID',
            'backup_secret'     => 'CBW_BACKUP_SECRET',
            'db'                => 'CBW_DB',
            'merknaam'          => 'CBW_MERKNAAM',
            'accent'            => 'CBW_ACCENT',
        ] as $sleutel => $env) {
            $uit = getenv($env);
            if ($uit !== false && $uit !== '') {
                $waarden[$sleutel] = $uit;
            }
        }

        $waarden += [
            'hostbill_veld' => 'Microsoft tenant',
            'cipp_scope'    => '',
            'db'            => dirname(__DIR__) . '/data/cbw.sqlite',
            'merknaam'      => 'Cbw-portaal',
            'accent'        => '#1f4a8f',
            'link_geldig'   => 60 * 60 * 24 * 30, // een ondertekende klantlink is een maand geldig
        ];

        return new self($waarden);
    }

    public function get(string $sleutel, mixed $standaard = null): mixed
    {
        return $this->waarden[$sleutel] ?? $standaard;
    }

    public function verplicht(string $sleutel): string
    {
        $waarde = (string)($this->waarden[$sleutel] ?? '');
        if ($waarde === '') {
            throw new RuntimeException("Instelling '{$sleutel}' ontbreekt. Zie config.voorbeeld.php.");
        }
        return $waarde;
    }

    public function hostbill(): HostBill
    {
        return new HostBill(
            $this->verplicht('hostbill_url'),
            $this->verplicht('hostbill_api_id'),
            $this->verplicht('hostbill_api_key'),
        );
    }

    public function cipp(): Cipp
    {
        $scope = (string)$this->get('cipp_scope', '');
        if ($scope === '') {
            // Zonder expliciete scope gebruiken we de CIPP-app zelf als doelgroep.
            $scope = 'api://' . $this->verplicht('cipp_client_id') . '/.default';
        }

        return new Cipp(
            $this->verplicht('cipp_url'),
            $this->verplicht('cipp_tenant_id'),
            $this->verplicht('cipp_client_id'),
            $this->verplicht('cipp_secret'),
            $scope,
        );
    }

    /**
     * De back-upbron, of null als er geen is ingesteld. Zonder bron blijven c1 en c2 handwerk -
     * het portaal verzint geen back-up die het niet kan zien.
     */
    public function backupBron(): ?Backup\Bron
    {
        $soort = strtolower(trim((string)$this->get('backup_bron', '')));

        return match ($soort) {
            'ninjaone', 'ninja' => new Backup\NinjaOne(
                $this->verplicht('backup_url'),
                $this->verplicht('backup_id'),
                $this->verplicht('backup_secret'),
            ),
            'datto', 'dattosaas' => new Backup\DattoSaaS(
                (string)$this->get('backup_url', 'https://api.datto.com'),
                $this->verplicht('backup_id'),
                $this->verplicht('backup_secret'),
            ),
            default => null,
        };
    }

    public function dossier(): Dossier
    {
        return new Dossier((string)$this->get('db'));
    }

    public function link(): Link
    {
        return new Link($this->verplicht('link_secret'), (int)$this->get('link_geldig'));
    }
}
