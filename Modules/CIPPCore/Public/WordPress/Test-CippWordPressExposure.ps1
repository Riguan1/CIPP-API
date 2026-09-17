function Test-CippWordPressExposure {
    <#
    .SYNOPSIS
    Probes the paths a WordPress site most often leaves reachable, and reports what answered.

    .DESCRIPTION
    Every probe is a plain GET for a path an anonymous visitor could request anyway. Nothing is
    submitted, no password is tried, and no parameter is crafted to provoke an error: the scan
    reads what the site publishes and stops there. That is a deliberate limit - it means the report
    can be produced for a live customer site during business hours without any risk of changing or
    breaking it, and it also means an issue that only an authenticated or intrusive test would find
    is out of reach here.

    A 200 response is not treated as proof on its own. Many WordPress installs answer every unknown
    path with a themed 404 page carrying status 200, so a random path is requested first to
    establish that behaviour, and each probe additionally requires content that matches what the
    file being looked for actually contains. A wp-config backup is only reported when the response
    really does contain database constants.

    .PARAMETER BaseUri
    Root URL of the site, as the scan resolved it.

    .PARAMETER TimeoutSeconds
    Per-request timeout. Defaults to 15.

    .PARAMETER MaxRequests
    Upper bound on requests made here. The probes stop when it is reached and the checks that were
    not run are reported as Unknown rather than as passes.

    .EXAMPLE
    Test-CippWordPressExposure -BaseUri 'https://example.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uri]$BaseUri,
        [int]$TimeoutSeconds = 15,
        [int]$MaxRequests = 30
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $RequestsMade = 0

    # A hashtable rather than a plain counter: the probe scriptblock runs in a child scope, where
    # assigning to a captured variable would only shadow it, and one scan must never see another's
    # count the way a script-scoped variable in a reused worker would allow.
    $State = @{ Requests = 0 }
    $Probe = {
        param([string]$Path)
        $Target = $null
        if (-not [System.Uri]::TryCreate($BaseUri, $Path, [ref]$Target)) { return $null }
        $State.Requests++
        return Invoke-CippWordPressProbe -Uri $Target -TimeoutSeconds $TimeoutSeconds -AllowInsecureCertificate
    }

    # --- Soft 404 baseline ---------------------------------------------------------------
    # A path that cannot exist. If the site answers it with 200, status alone proves nothing and
    # every probe below has to rely on its content signature.
    $BaselinePath = 'cipp-scan-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 12))
    $Baseline = & $Probe $BaselinePath
    $SoftNotFound = $Baseline -and $Baseline.Success -and $Baseline.StatusCode -eq 200

    if ($SoftNotFound) {
        $Findings.Add((New-CippWordPressFinding -Id 'WP-SOFT-404' -Category 'Exposure' -Title 'The site answers unknown URLs with 200 OK' -Severity Info -Status Info `
                    -Evidence "A request for /$BaselinePath returned 200 instead of 404." `
                    -Recommendation 'Not a vulnerability, but it hides missing pages from monitoring and from scanners. Findings below were confirmed on response content rather than status code.'))
    }

    # Path, what it means if it is really there, and the content that proves it is.
    $FileProbes = @(
        @{ Path = 'wp-config.php.bak'; Id = 'WP-CONFIG-BACKUP'; Signature = 'DB_PASSWORD|DB_NAME|DB_USER'; Severity = 'Critical'
            Title = 'A wp-config backup is downloadable'
            Recommendation = 'Delete it from the web root today and rotate the database password, the WordPress salts and any API keys it contained. Anyone who has fetched this file has your database credentials.'
        }
        @{ Path = 'wp-config.php.save'; Id = 'WP-CONFIG-BACKUP'; Signature = 'DB_PASSWORD|DB_NAME|DB_USER'; Severity = 'Critical'
            Title = 'A wp-config backup is downloadable'
            Recommendation = 'Delete it from the web root today and rotate the database password, the WordPress salts and any API keys it contained.'
        }
        @{ Path = 'wp-config.php.old'; Id = 'WP-CONFIG-BACKUP'; Signature = 'DB_PASSWORD|DB_NAME|DB_USER'; Severity = 'Critical'
            Title = 'A wp-config backup is downloadable'
            Recommendation = 'Delete it from the web root today and rotate the database password, the WordPress salts and any API keys it contained.'
        }
        @{ Path = 'wp-config.txt'; Id = 'WP-CONFIG-BACKUP'; Signature = 'DB_PASSWORD|DB_NAME|DB_USER'; Severity = 'Critical'
            Title = 'A wp-config backup is downloadable'
            Recommendation = 'Delete it from the web root today and rotate the database password, the WordPress salts and any API keys it contained.'
        }
        @{ Path = '.env'; Id = 'WP-ENV-FILE'; Signature = '(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*='; Severity = 'Critical'
            Title = 'An .env file is downloadable'
            Recommendation = 'Move it outside the web root and rotate every secret it holds. .env files routinely carry database, mail and payment credentials.'
        }
        @{ Path = '.git/config'; Id = 'WP-GIT-EXPOSED'; Signature = '\[core\]|repositoryformatversion'; Severity = 'High'
            Title = 'The .git directory is served to visitors'
            Recommendation = 'Block /.git in the web server configuration. A published repository lets anyone reconstruct your source, and its history often still contains credentials that were removed later.'
        }
        @{ Path = 'wp-content/debug.log'; Id = 'WP-DEBUG-LOG'; Signature = 'PHP (Notice|Warning|Fatal error|Deprecated)|Stack trace'; Severity = 'High'
            Title = 'The WordPress debug log is downloadable'
            Recommendation = 'Set WP_DEBUG_LOG to false in wp-config.php and delete the file. Debug logs disclose absolute paths, queries and sometimes session data.'
        }
        @{ Path = 'readme.html'; Id = 'WP-README'; Signature = 'WordPress'; Severity = 'Low'
            Title = 'readme.html is reachable and names the WordPress version'
            Recommendation = 'Delete readme.html after each update. It hands an attacker your exact version without them having to fingerprint anything.'
        }
        @{ Path = 'wp-admin/install.php'; Id = 'WP-INSTALLER'; Signature = 'weblog_title|famous five-minute WordPress installation'; Severity = 'Critical'
            Title = 'The WordPress installer is reachable'
            Recommendation = 'This lets anyone reinstall the site and take ownership of it. Complete or remove the installation immediately.'
        }
        @{ Path = 'wp-content/uploads/'; Id = 'WP-DIRECTORY-LISTING'; Signature = 'Index of /|<title>Index of'; Severity = 'Medium'
            Title = 'The uploads directory lists its contents'
            Recommendation = 'Disable directory indexing (Options -Indexes on Apache, autoindex off on nginx). A listing exposes documents that were uploaded but never linked.'
        }
        @{ Path = 'wp-content/plugins/'; Id = 'WP-DIRECTORY-LISTING-PLUGINS'; Signature = 'Index of /|<title>Index of'; Severity = 'Medium'
            Title = 'The plugins directory lists its contents'
            Recommendation = 'Disable directory indexing. The listing gives an attacker the full plugin inventory, including plugins that are installed but deactivated.'
        }
    )

    foreach ($FileProbe in $FileProbes) {
        if ($State.Requests -ge $MaxRequests) {
            $Findings.Add((New-CippWordPressFinding -Id $FileProbe.Id -Category 'Exposure' -Title $FileProbe.Title -Severity $FileProbe.Severity -Status Unknown `
                        -Evidence "Not checked: the scan reached its limit of $MaxRequests requests." `
                        -Recommendation 'Re-run the scan with a higher request limit to check this.'))
            continue
        }

        $Response = & $Probe $FileProbe.Path
        if (-not $Response -or -not $Response.Success) { continue }

        $Matched = $Response.StatusCode -eq 200 -and $Response.Content -match $FileProbe.Signature
        if ($Matched) {
            $Findings.Add((New-CippWordPressFinding -Id $FileProbe.Id -Category 'Exposure' -Title $FileProbe.Title -Severity $FileProbe.Severity -Status Fail `
                        -Evidence "$($Response.FinalUri) returned $($Response.StatusCode) with matching content." `
                        -Recommendation $FileProbe.Recommendation))
        } elseif ($Response.StatusCode -eq 200 -and $FileProbe.Severity -eq 'Critical' -and -not $SoftNotFound) {
            # 200 on a path that should not exist, but the content is not what the file would
            # contain. Worth a human look rather than a pass, given what these files hold.
            $Findings.Add((New-CippWordPressFinding -Id $FileProbe.Id -Category 'Exposure' -Title $FileProbe.Title -Severity $FileProbe.Severity -Status Unknown `
                        -Evidence "$($Response.FinalUri) returned 200 but the response did not look like the file itself." `
                        -Recommendation 'Open the URL to confirm what is being served there.'))
        }
    }

    # --- XML-RPC -------------------------------------------------------------------------
    if ($State.Requests -lt $MaxRequests) {
        $XmlRpc = & $Probe 'xmlrpc.php'
        if ($XmlRpc -and $XmlRpc.Success) {
            # WordPress answers a GET with 405 and this exact sentence when the endpoint is live.
            $Enabled = $XmlRpc.Content -match 'XML-RPC server accepts POST requests only' -or
                ($XmlRpc.StatusCode -eq 405 -and $XmlRpc.Content -match 'XML-RPC')
            if ($Enabled) {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-XMLRPC' -Category 'Exposure' -Title 'XML-RPC is enabled' -Severity Medium -Status Fail `
                            -Evidence "$($XmlRpc.FinalUri) returned $($XmlRpc.StatusCode): XML-RPC server accepts POST requests only." `
                            -Recommendation 'Block xmlrpc.php unless Jetpack or the WordPress mobile app needs it. It allows hundreds of password guesses in a single request through system.multicall, and its pingback method can be abused to attack other sites from yours.' `
                            -Reference 'https://developer.wordpress.org/apis/xml-rpc/'))
            } else {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-XMLRPC' -Category 'Exposure' -Title 'XML-RPC is not reachable' -Severity Medium -Status Pass `
                            -Evidence "$($XmlRpc.FinalUri) returned $($XmlRpc.StatusCode)."))
            }
        }
    }

    # --- User enumeration via the REST API -----------------------------------------------
    if ($State.Requests -lt $MaxRequests) {
        $Users = & $Probe 'wp-json/wp/v2/users'
        if ($Users -and $Users.Success) {
            if ($Users.StatusCode -eq 200 -and $Users.Content -match '"slug"\s*:') {
                $Names = @([regex]::Matches($Users.Content, '"slug"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                $Shown = @($Names | Select-Object -First 5)
                $Evidence = "$($Users.FinalUri) listed $($Names.Count) account name(s)"
                if ($Shown.Count -gt 0) { $Evidence = '{0}: {1}' -f $Evidence, ($Shown -join ', ') }
                $Findings.Add((New-CippWordPressFinding -Id 'WP-REST-USERS' -Category 'Enumeration' -Title 'The REST API lists account names' -Severity Medium -Status Fail `
                            -Evidence $Evidence `
                            -Recommendation 'Restrict /wp-json/wp/v2/users to authenticated requests. Usernames are half of a password-guessing attack, and this endpoint hands over the whole list including administrators.' `
                            -Reference 'https://developer.wordpress.org/rest-api/reference/users/'))
            } else {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-REST-USERS' -Category 'Enumeration' -Title 'The REST API does not list account names' -Severity Medium -Status Pass `
                            -Evidence "$($Users.FinalUri) returned $($Users.StatusCode)."))
            }
        }
    }

    # --- User enumeration via author archives ---------------------------------------------
    if ($State.Requests -lt $MaxRequests) {
        $Author = & $Probe '?author=1'
        if ($Author -and $Author.Success) {
            $AuthorMatch = $null
            if ($Author.FinalUri) { $AuthorMatch = [regex]::Match($Author.FinalUri, '/author/([^/?#]+)') }
            if ($AuthorMatch -and $AuthorMatch.Success) {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-AUTHOR-ENUM' -Category 'Enumeration' -Title 'Author archives disclose the login name' -Severity Medium -Status Fail `
                            -Evidence "?author=1 redirected to $($Author.FinalUri), disclosing '$($AuthorMatch.Groups[1].Value)'." `
                            -Recommendation 'Block ?author= requests, or set each user''s nickname and display name to something other than their login name so the archive slug stops matching it.'))
            } else {
                $Findings.Add((New-CippWordPressFinding -Id 'WP-AUTHOR-ENUM' -Category 'Enumeration' -Title 'Author archives do not disclose a login name' -Severity Medium -Status Pass `
                            -Evidence "?author=1 returned $($Author.StatusCode) without redirecting to an author slug."))
            }
        }
    }

    # --- Login page ----------------------------------------------------------------------
    if ($State.Requests -lt $MaxRequests) {
        $Login = & $Probe 'wp-login.php'
        if ($Login -and $Login.Success -and $Login.StatusCode -eq 200 -and $Login.Content -match 'user_login|wp-submit') {
            $Findings.Add((New-CippWordPressFinding -Id 'WP-LOGIN-EXPOSED' -Category 'Exposure' -Title 'The login page is reachable from anywhere' -Severity Low -Status Info `
                        -Evidence "$($Login.FinalUri) serves the standard WordPress login form." `
                        -Recommendation 'Normal for most sites, and worth hardening: require MFA for every account, add login rate limiting, and restrict wp-admin and wp-login.php by IP address where the customer works from fixed locations.'))
        }
    }

    # --- wp-cron -------------------------------------------------------------------------
    if ($State.Requests -lt $MaxRequests) {
        $Cron = & $Probe 'wp-cron.php'
        if ($Cron -and $Cron.Success -and $Cron.StatusCode -in @(200, 204)) {
            $Findings.Add((New-CippWordPressFinding -Id 'WP-CRON-EXPOSED' -Category 'Exposure' -Title 'wp-cron.php can be triggered by anyone' -Severity Low -Status Warn `
                        -Evidence "$($Cron.FinalUri) returned $($Cron.StatusCode)." `
                        -Recommendation 'Set DISABLE_WP_CRON to true in wp-config.php and run wp-cron from a real scheduled task. Left open, it is an easy way to load the server by requesting it repeatedly.'))
        }
    }

    $RequestsMade = $State.Requests

    return [PSCustomObject]@{
        Findings     = @($Findings)
        RequestsMade = $RequestsMade
        SoftNotFound = $SoftNotFound
    }
}
