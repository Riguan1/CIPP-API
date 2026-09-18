<?php
/**
 * Kopieer naar config.php en vul in. config.php staat in .gitignore: geheimen horen niet in git.
 * Elke sleutel kan ook als omgevingsvariabele (zie src/Config.php).
 */
return [
    // --- HostBill -------------------------------------------------------------------------------
    // Settings > Security > API access. Geef de sleutel alleen getClients en getClientDetails.
    'hostbill_url'     => 'https://billing.voorbeeld.nl',
    'hostbill_api_id'  => '',
    'hostbill_api_key' => '',
    // Naam van het custom field in HostBill waarin de Microsoft-tenant staat. Leeg laten mag:
    // dan koppel je de tenant met de hand in het beheerscherm.
    'hostbill_veld'    => 'Microsoft tenant',

    // --- CIPP -----------------------------------------------------------------------------------
    // Maak in CIPP onder Settings > API access een client met de rol Tenant.Reports.Read.
    'cipp_url'       => 'https://cipp-voorbeeld.azurewebsites.net',
    'cipp_tenant_id' => '',   // uw eigen Entra tenant id
    'cipp_client_id' => '',   // application (client) id van de CIPP API-client
    'cipp_secret'    => '',
    // Leeg laten geeft api://<cipp_client_id>/.default, wat in de meeste installaties klopt.
    'cipp_scope'     => '',

    // --- Back-up (Datto SaaS Protection of NinjaOne) ----------------------------------------------
    // Leeg laten mag: dan blijven c1 en c2 handwerk.
    //   'datto'    -> backup_id/secret zijn de publieke en geheime sleutel uit het Datto Partner
    //                 Portal (Admin > Integrations > Create API Key). backup_url is meestal
    //                 https://api.datto.com
    //   'ninjaone' -> backup_id/secret zijn client id en secret van een machine-to-machine app met
    //                 scope 'monitoring'. backup_url is uw regio: https://eu.ninjarmm.com,
    //                 https://app.ninjarmm.com of https://oc.ninjarmm.com
    'backup_bron'   => '',
    'backup_url'    => '',
    'backup_id'     => '',
    'backup_secret' => '',

    // --- Portaal --------------------------------------------------------------------------------
    // Zelfde waarde als GEDEELD_GEHEIM in hostbill/ga-naar-portaal.php.
    // Maak er een met: php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"
    'link_secret'      => '',
    'admin_wachtwoord' => '',
    'portaal_url'      => 'https://portaal.voorbeeld.nl',
    'db'               => __DIR__ . '/data/cbw.sqlite',

    // --- Uiterlijk ------------------------------------------------------------------------------
    'merknaam' => 'Uw organisatie',
    'accent'   => '#1f4a8f',
];
