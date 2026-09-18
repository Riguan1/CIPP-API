<?php
declare(strict_types=1);

namespace CbwPortal;

use PDO;

/**
 * Opslag per HostBill-klant: de koppeling naar een tenant, de handmatige antwoorden met hun
 * notities, en de laatst opgehaalde stand uit CIPP.
 *
 * SQLite is de standaard omdat dit portaal op één server draait en de dataset klein is. De DSN is
 * instelbaar, dus MySQL kan ook; het schema gebruikt geen SQLite-specifieke types.
 */
final class Dossier
{
    private PDO $db;

    public function __construct(string $pad)
    {
        $dsn = str_contains($pad, ':') ? $pad : 'sqlite:' . $pad;

        if (str_starts_with($dsn, 'sqlite:')) {
            $bestand = substr($dsn, 7);
            $map = dirname($bestand);
            if (!is_dir($map)) {
                mkdir($map, 0750, true);
            }
        }

        $this->db = new PDO($dsn, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->migreren();
    }

    private function migreren(): void
    {
        $this->db->exec('CREATE TABLE IF NOT EXISTS klant (
            client_id   VARCHAR(32) PRIMARY KEY,
            tenant      VARCHAR(255),
            naam        VARCHAR(255),
            in_scope    VARCHAR(16) DEFAULT "onbekend",
            sector      VARCHAR(64),
            bijgewerkt  VARCHAR(32)
        )');

        $this->db->exec('CREATE TABLE IF NOT EXISTS antwoord (
            client_id   VARCHAR(32) NOT NULL,
            controle    VARCHAR(16) NOT NULL,
            status      VARCHAR(16),
            notitie     TEXT,
            door        VARCHAR(128),
            bijgewerkt  VARCHAR(32),
            PRIMARY KEY (client_id, controle)
        )');

        $this->db->exec('CREATE TABLE IF NOT EXISTS stand (
            client_id   VARCHAR(32) PRIMARY KEY,
            json        TEXT,
            opgehaald   VARCHAR(32),
            fout        TEXT
        )');
    }

    public function klant(string $clientId): ?array
    {
        $q = $this->db->prepare('SELECT * FROM klant WHERE client_id = ?');
        $q->execute([$clientId]);
        return $q->fetch() ?: null;
    }

    /** @return array<int, array> */
    public function klanten(): array
    {
        return $this->db->query('SELECT * FROM klant ORDER BY naam')->fetchAll();
    }

    public function klantOpslaan(string $clientId, ?string $tenant, string $naam, string $inScope = 'onbekend', ?string $sector = null): void
    {
        $bestaat = $this->klant($clientId) !== null;
        if ($bestaat) {
            $q = $this->db->prepare('UPDATE klant SET tenant = ?, naam = ?, in_scope = ?, sector = ?, bijgewerkt = ? WHERE client_id = ?');
            $q->execute([$tenant, $naam, $inScope, $sector, gmdate('c'), $clientId]);
        } else {
            $q = $this->db->prepare('INSERT INTO klant (client_id, tenant, naam, in_scope, sector, bijgewerkt) VALUES (?, ?, ?, ?, ?, ?)');
            $q->execute([$clientId, $tenant, $naam, $inScope, $sector, gmdate('c')]);
        }
    }

    /** @return array<string, array{status: ?string, notitie: ?string, door: ?string, bijgewerkt: ?string}> */
    public function antwoorden(string $clientId): array
    {
        $q = $this->db->prepare('SELECT controle, status, notitie, door, bijgewerkt FROM antwoord WHERE client_id = ?');
        $q->execute([$clientId]);

        $uit = [];
        foreach ($q->fetchAll() as $rij) {
            $uit[(string)$rij['controle']] = [
                'status'     => $rij['status'] !== '' ? $rij['status'] : null,
                'notitie'    => $rij['notitie'],
                'door'       => $rij['door'],
                'bijgewerkt' => $rij['bijgewerkt'],
            ];
        }
        return $uit;
    }

    public function antwoordOpslaan(string $clientId, string $controle, ?string $status, ?string $notitie, string $door): void
    {
        if ($status !== null && !in_array($status, Controls::STATUSSEN, true)) {
            $status = null;
        }

        $q = $this->db->prepare('SELECT 1 FROM antwoord WHERE client_id = ? AND controle = ?');
        $q->execute([$clientId, $controle]);

        if ($q->fetch()) {
            $u = $this->db->prepare('UPDATE antwoord SET status = ?, notitie = ?, door = ?, bijgewerkt = ? WHERE client_id = ? AND controle = ?');
            $u->execute([$status, $notitie, $door, gmdate('c'), $clientId, $controle]);
        } else {
            $i = $this->db->prepare('INSERT INTO antwoord (client_id, controle, status, notitie, door, bijgewerkt) VALUES (?, ?, ?, ?, ?, ?)');
            $i->execute([$clientId, $controle, $status, $notitie, $door, gmdate('c')]);
        }
    }

    public function standOpslaan(string $clientId, ?array $stand, ?string $fout = null): void
    {
        $json = $stand !== null ? json_encode($stand, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null;

        $q = $this->db->prepare('SELECT 1 FROM stand WHERE client_id = ?');
        $q->execute([$clientId]);

        if ($q->fetch()) {
            // Bij een fout laten we de laatst bekende stand staan; hem weggooien zou de klant
            // een leeg scherm geven terwijl er gisteren nog gegevens waren.
            if ($stand === null) {
                $u = $this->db->prepare('UPDATE stand SET fout = ? WHERE client_id = ?');
                $u->execute([$fout, $clientId]);
            } else {
                $u = $this->db->prepare('UPDATE stand SET json = ?, opgehaald = ?, fout = NULL WHERE client_id = ?');
                $u->execute([$json, gmdate('c'), $clientId]);
            }
        } else {
            $i = $this->db->prepare('INSERT INTO stand (client_id, json, opgehaald, fout) VALUES (?, ?, ?, ?)');
            $i->execute([$clientId, $json, $stand !== null ? gmdate('c') : null, $fout]);
        }
    }

    /** @return array{stand: ?array, opgehaald: ?string, fout: ?string} */
    public function stand(string $clientId): array
    {
        $q = $this->db->prepare('SELECT json, opgehaald, fout FROM stand WHERE client_id = ?');
        $q->execute([$clientId]);
        $rij = $q->fetch();

        if (!$rij) {
            return ['stand' => null, 'opgehaald' => null, 'fout' => null];
        }

        $stand = $rij['json'] ? json_decode((string)$rij['json'], true) : null;

        return [
            'stand'     => is_array($stand) ? $stand : null,
            'opgehaald' => $rij['opgehaald'],
            'fout'      => $rij['fout'],
        ];
    }
}
