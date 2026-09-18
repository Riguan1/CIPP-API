<?php
declare(strict_types=1);

/**
 * Kleine autoloader. Dit portaal heeft geen composer nodig: het is een handvol klassen in src/.
 */
spl_autoload_register(static function (string $klasse): void {
    if (!str_starts_with($klasse, 'CbwPortal\\')) {
        return;
    }
    $pad = __DIR__ . '/' . str_replace('\\', '/', substr($klasse, strlen('CbwPortal\\'))) . '.php';
    if (is_file($pad)) {
        require $pad;
    }
});

mb_internal_encoding('UTF-8');
date_default_timezone_set('Europe/Amsterdam');
