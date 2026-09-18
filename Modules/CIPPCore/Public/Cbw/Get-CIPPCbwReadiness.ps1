function Get-CIPPCbwReadiness {
    <#
    .SYNOPSIS
        Maps live tenant configuration onto the duty-of-care controls of the Dutch Cyberbeveiligingswet.

    .DESCRIPTION
        Collects the signals that Microsoft 365 can actually prove and expresses each one as a verdict on a
        control of the Cbw duty of care (NIS2 art. 21(2)). The control identifiers match the ones used by the
        Cbw-wegwijzer in Tools/CbwWegwijzer, so its self-assessment can be pre-filled from a tenant instead of
        being answered from memory.

        Every check runs in isolation: a Graph call that fails, is unlicensed or is unavailable yields a control
        with status 'onbekend' carrying the reason, and never takes the rest of the report down with it.

        Statuses follow the wegwijzer: geregeld / deels / open / onbekend. Controls that Microsoft 365 cannot
        prove at all - backups held outside the tenant, supplier contracts, board training - are returned
        separately under NotDetectable with the reason, so nobody mistakes a missing signal for a passing one.

    .PARAMETER TenantFilter
        The tenant to inspect. A single tenant only; this report is too Graph-heavy to fan out.

    .PARAMETER Headers
        Request headers, forwarded to the helpers that log on the caller's behalf.

    .EXAMPLE
        Get-CIPPCbwReadiness -TenantFilter 'contoso.onmicrosoft.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        $Headers
    )

    $Controls = [System.Collections.Generic.List[object]]::new()

    # Turns a coverage percentage into one of the wegwijzer's statuses.
    function Get-CbwVerdict {
        param([double]$Percentage, [double]$Good = 95, [double]$Partial = 50)
        if ($Percentage -ge $Good) { return 'geregeld' }
        if ($Percentage -ge $Partial) { return 'deels' }
        return 'open'
    }

    function Add-CbwControl {
        param(
            [string]$ControlId,
            [string]$Article,
            [string]$Status,
            [string]$Headline,
            [string]$Detail,
            [string]$Source,
            $Metric
        )
        $Controls.Add([PSCustomObject]@{
                ControlId = $ControlId
                Article   = $Article
                Status    = $Status
                Headline  = $Headline
                Detail    = $Detail
                Source    = $Source
                Metric    = $Metric
            })
    }

    # Records a check that could not run. An unavailable signal is never a pass.
    function Add-CbwUnknown {
        param([string]$ControlId, [string]$Article, [string]$Source, $ErrorRecord)
        $Reason = if ($ErrorRecord) { (Get-CippException -Exception $ErrorRecord).NormalizedError } else { 'Geen gegevens ontvangen' }
        Add-CbwControl -ControlId $ControlId -Article $Article -Status 'onbekend' -Source $Source `
            -Headline 'Niet vast te stellen' -Detail "Deze controle kon niet worden uitgelezen: $Reason"
    }

    # --- j1 / j2 / i2: authentication and administrative accounts -------------------------------------
    try {
        $Registration = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$top=999' -tenantid $TenantFilter)
        $Members = @($Registration | Where-Object { $_.userType -ne 'guest' })

        if ($Members.Count -gt 0) {
            $MfaCapable = @($Members | Where-Object { $_.isMfaCapable -eq $true })
            $Percentage = [math]::Round(($MfaCapable.Count / $Members.Count) * 100, 1)
            Add-CbwControl -ControlId 'j1' -Article 'art. 21.2 j' -Status (Get-CbwVerdict -Percentage $Percentage -Good 98 -Partial 60) `
                -Headline "$($MfaCapable.Count) van $($Members.Count) gebruikers ($Percentage%) kan MFA gebruiken" `
                -Detail 'Gebaseerd op geregistreerde verificatiemethoden in Entra ID. Let op: dit toont dat MFA kán worden gebruikt, niet dat het via voorwaardelijke toegang wordt afgedwongen.' `
                -Source 'Entra ID - userRegistrationDetails' `
                -Metric ([PSCustomObject]@{ Value = $MfaCapable.Count; Total = $Members.Count; Percentage = $Percentage })

            $PhishResistant = @($Members | Where-Object { $_.isMfaCapable -eq $true -and ($_.methodsRegistered -match 'fido2|windowsHelloForBusiness|x509Certificate') })
            $PhishPercentage = [math]::Round(($PhishResistant.Count / $Members.Count) * 100, 1)
            Add-CbwControl -ControlId 'j1-phish' -Article 'art. 21.2 j' -Status 'onbekend' `
                -Headline "$($PhishResistant.Count) van $($Members.Count) gebruikers ($PhishPercentage%) heeft een phishingbestendige methode" `
                -Detail 'Passkey, FIDO2, Windows Hello for Business of certificaat. De wet eist geen phishingbestendige MFA, maar toezichthouders vragen er wel naar.' `
                -Source 'Entra ID - userRegistrationDetails' `
                -Metric ([PSCustomObject]@{ Value = $PhishResistant.Count; Total = $Members.Count; Percentage = $PhishPercentage })
        } else {
            Add-CbwUnknown -ControlId 'j1' -Article 'art. 21.2 j' -Source 'Entra ID - userRegistrationDetails'
        }

        $Admins = @($Registration | Where-Object { $_.isAdmin -eq $true })
        if ($Admins.Count -gt 0) {
            $AdminsWithMfa = @($Admins | Where-Object { $_.isMfaCapable -eq $true })
            $AdminPercentage = [math]::Round(($AdminsWithMfa.Count / $Admins.Count) * 100, 1)
            Add-CbwControl -ControlId 'j2' -Article 'art. 21.2 j' -Status (Get-CbwVerdict -Percentage $AdminPercentage -Good 100 -Partial 80) `
                -Headline "$($AdminsWithMfa.Count) van $($Admins.Count) beheerders ($AdminPercentage%) kan MFA gebruiken" `
                -Detail 'Beheerdersaccounts zonder MFA zijn het eerste dat een toezichthouder opvraagt. Hier telt alleen 100%.' `
                -Source 'Entra ID - userRegistrationDetails' `
                -Metric ([PSCustomObject]@{ Value = $AdminsWithMfa.Count; Total = $Admins.Count; Percentage = $AdminPercentage })
        } else {
            Add-CbwUnknown -ControlId 'j2' -Article 'art. 21.2 j' -Source 'Entra ID - userRegistrationDetails'
        }
    } catch {
        Add-CbwUnknown -ControlId 'j1' -Article 'art. 21.2 j' -Source 'Entra ID - userRegistrationDetails' -ErrorRecord $_
        Add-CbwUnknown -ControlId 'j2' -Article 'art. 21.2 j' -Source 'Entra ID - userRegistrationDetails' -ErrorRecord $_
    }

    try {
        $GlobalAdmins = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members?`$select=id,displayName,userPrincipalName" -tenantid $TenantFilter)
        $Count = $GlobalAdmins.Count
        # Microsoft's own guidance: fewer than five permanent global administrators, at least two for continuity.
        $Status = if ($Count -ge 2 -and $Count -le 4) { 'geregeld' } elseif ($Count -le 6) { 'deels' } else { 'open' }
        Add-CbwControl -ControlId 'i2' -Article 'art. 21.2 i' -Status $Status `
            -Headline "$Count permanente global administrators" `
            -Detail 'Richtlijn: twee tot vier permanente global admins, de rest tijdelijk via PIM. Meer permanente beheerders betekent een groter aanvalsoppervlak dan de zorgplicht toelaat.' `
            -Source 'Entra ID - directoryRoles' `
            -Metric ([PSCustomObject]@{ Value = $Count; Total = $null; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'i2' -Article 'art. 21.2 i' -Source 'Entra ID - directoryRoles' -ErrorRecord $_
    }

    # --- j3 / j5: conditional access ------------------------------------------------------------------
    try {
        $Policies = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -tenantid $TenantFilter)
        $Enabled = @($Policies | Where-Object { $_.state -eq 'enabled' })

        $LegacyBlocks = @($Enabled | Where-Object {
                $_.conditions.clientAppTypes -and
                ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or $_.conditions.clientAppTypes -contains 'other') -and
                $_.conditions.clientAppTypes -notcontains 'all' -and
                $_.grantControls.builtInControls -contains 'block'
            })
        if ($LegacyBlocks.Count -gt 0) {
            Add-CbwControl -ControlId 'j3' -Article 'art. 21.2 j' -Status 'geregeld' `
                -Headline "Verouderde authenticatie wordt geblokkeerd door $($LegacyBlocks.Count) beleid(en)" `
                -Detail "Gevonden: $(($LegacyBlocks.displayName | Select-Object -First 3) -join ', '). Controleer de aanmeldlogboeken of er nog uitzonderingen op staan." `
                -Source 'Entra ID - voorwaardelijke toegang'
        } else {
            Add-CbwControl -ControlId 'j3' -Article 'art. 21.2 j' -Status 'open' `
                -Headline 'Geen ingeschakeld beleid gevonden dat verouderde authenticatie blokkeert' `
                -Detail 'Zonder blokkade blijft wachtwoordspray op oude protocollen mogelijk, ongeacht de MFA-dekking.' `
                -Source 'Entra ID - voorwaardelijke toegang'
        }

        $Excluded = @($Enabled.conditions.users.excludeUsers | Where-Object { $_ } | Select-Object -Unique)
        Add-CbwControl -ControlId 'j5' -Article 'art. 21.2 j' -Status 'onbekend' `
            -Headline "$($Excluded.Count) account(s) uitgezonderd van voorwaardelijke toegang" `
            -Detail 'Break-glass-accounts horen hier te staan - en niets anders. Loop de lijst na: elke uitzondering die geen noodaccount is, is een gat.' `
            -Source 'Entra ID - voorwaardelijke toegang' `
            -Metric ([PSCustomObject]@{ Value = $Excluded.Count; Total = $Enabled.Count; Percentage = $null })

        Add-CbwControl -ControlId 'ca-totaal' -Article 'art. 21.2 i' -Status 'onbekend' `
            -Headline "$($Enabled.Count) van $($Policies.Count) beleidsregels voor voorwaardelijke toegang staan aan" `
            -Detail 'Beleid dat op rapportagemodus of uit staat, beschermt niets.' `
            -Source 'Entra ID - voorwaardelijke toegang' `
            -Metric ([PSCustomObject]@{ Value = $Enabled.Count; Total = $Policies.Count; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'j3' -Article 'art. 21.2 j' -Source 'Entra ID - voorwaardelijke toegang' -ErrorRecord $_
        Add-CbwUnknown -ControlId 'j5' -Article 'art. 21.2 j' -Source 'Entra ID - voorwaardelijke toegang' -ErrorRecord $_
    }

    # --- h2 / e1 / a4: devices ------------------------------------------------------------------------
    try {
        $Devices = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,isEncrypted,complianceState,operatingSystem,lastSyncDateTime" -tenantid $TenantFilter)
        if ($Devices.Count -gt 0) {
            $Encrypted = @($Devices | Where-Object { $_.isEncrypted -eq $true })
            $EncryptionPercentage = [math]::Round(($Encrypted.Count / $Devices.Count) * 100, 1)
            Add-CbwControl -ControlId 'h2' -Article 'art. 21.2 h' -Status (Get-CbwVerdict -Percentage $EncryptionPercentage -Good 98 -Partial 70) `
                -Headline "$($Encrypted.Count) van $($Devices.Count) apparaten ($EncryptionPercentage%) is versleuteld" `
                -Detail 'Schijfversleuteling volgens Intune. Een niet-versleutelde laptop die kwijtraakt, is een datalek dat u niet kunt afdekken.' `
                -Source 'Intune - managedDevices' `
                -Metric ([PSCustomObject]@{ Value = $Encrypted.Count; Total = $Devices.Count; Percentage = $EncryptionPercentage })

            $Compliant = @($Devices | Where-Object { $_.complianceState -eq 'compliant' })
            $CompliancePercentage = [math]::Round(($Compliant.Count / $Devices.Count) * 100, 1)
            Add-CbwControl -ControlId 'e1' -Article 'art. 21.2 e' -Status (Get-CbwVerdict -Percentage $CompliancePercentage -Good 95 -Partial 70) `
                -Headline "$($Compliant.Count) van $($Devices.Count) apparaten ($CompliancePercentage%) voldoet aan het nalevingsbeleid" `
                -Detail 'Naleving is een indicatie voor patchachterstand, niet het bewijs van een patchbeleid. Het beleid zelf en de termijnen per risicoklasse legt u apart vast.' `
                -Source 'Intune - managedDevices' `
                -Metric ([PSCustomObject]@{ Value = $Compliant.Count; Total = $Devices.Count; Percentage = $CompliancePercentage })

            $Stale = @($Devices | Where-Object { $_.lastSyncDateTime -and [datetime]$_.lastSyncDateTime -lt (Get-Date).AddDays(-30) })
            Add-CbwControl -ControlId 'a4' -Article 'art. 21.2 a' -Status ($(if ($Stale.Count -eq 0) { 'geregeld' } elseif ($Stale.Count -le ($Devices.Count * 0.1)) { 'deels' } else { 'open' })) `
                -Headline "$($Devices.Count) beheerde apparaten, waarvan $($Stale.Count) langer dan 30 dagen niet gesynchroniseerd" `
                -Detail 'Een inventarisatie met apparaten die al een maand zwijgen, is geen actuele inventarisatie. Ruim ze op of verklaar ze.' `
                -Source 'Intune - managedDevices' `
                -Metric ([PSCustomObject]@{ Value = $Devices.Count; Total = $Devices.Count; Percentage = $null })
        } else {
            Add-CbwUnknown -ControlId 'h2' -Article 'art. 21.2 h' -Source 'Intune - managedDevices'
            Add-CbwUnknown -ControlId 'e1' -Article 'art. 21.2 e' -Source 'Intune - managedDevices'
        }
    } catch {
        Add-CbwUnknown -ControlId 'h2' -Article 'art. 21.2 h' -Source 'Intune - managedDevices' -ErrorRecord $_
        Add-CbwUnknown -ControlId 'e1' -Article 'art. 21.2 e' -Source 'Intune - managedDevices' -ErrorRecord $_
    }

    # --- i1 / i5: accounts ----------------------------------------------------------------------------
    try {
        $Users = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users?`$top=999&`$select=id,userPrincipalName,accountEnabled,userType,assignedLicenses,signInActivity" -tenantid $TenantFilter)
        $Licensed = @($Users | Where-Object { $_.accountEnabled -eq $true -and $_.userType -eq 'Member' -and $_.assignedLicenses.Count -gt 0 })
        $Stale = @($Licensed | Where-Object {
                $LastSignIn = $_.signInActivity.lastSignInDateTime
                $LastSignIn -and [datetime]$LastSignIn -lt (Get-Date).AddDays(-90)
            })
        if ($Licensed.Count -gt 0) {
            $Status = if ($Stale.Count -eq 0) { 'geregeld' } elseif ($Stale.Count -le 2) { 'deels' } else { 'open' }
            Add-CbwControl -ControlId 'i1' -Article 'art. 21.2 i' -Status $Status `
                -Headline "$($Stale.Count) van $($Licensed.Count) actieve gelicentieerde accounts is 90 dagen niet gebruikt" `
                -Detail 'Slapende accounts met een licentie wijzen op uitdiensttreding die niet is afgerond. Dat is zowel een beveiligingsgat als een rekening die doorloopt.' `
                -Source 'Entra ID - signInActivity' `
                -Metric ([PSCustomObject]@{ Value = $Stale.Count; Total = $Licensed.Count; Percentage = $null })
        }

        $Guests = @($Users | Where-Object { $_.userType -eq 'Guest' })
        Add-CbwControl -ControlId 'i5' -Article 'art. 21.2 i' -Status 'onbekend' `
            -Headline "$($Guests.Count) gastaccounts in de tenant" `
            -Detail 'De wegwijzer kan tellen, niet beoordelen: of elk gastaccount een eigenaar en een reden heeft, moet u zelf vaststellen.' `
            -Source 'Entra ID - users' `
            -Metric ([PSCustomObject]@{ Value = $Guests.Count; Total = $Users.Count; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'i1' -Article 'art. 21.2 i' -Source 'Entra ID - users' -ErrorRecord $_
    }

    # --- i3: access reviews ---------------------------------------------------------------------------
    try {
        $Reviews = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions' -tenantid $TenantFilter)
        $Active = @($Reviews | Where-Object { $_.status -eq 'InProgress' -or $_.status -eq 'Applied' })
        Add-CbwControl -ControlId 'i3' -Article 'art. 21.2 i' -Status ($(if ($Active.Count -gt 0) { 'deels' } else { 'open' })) `
            -Headline "$($Reviews.Count) toegangsbeoordelingen ingericht, waarvan $($Active.Count) actief" `
            -Detail 'Een ingerichte beoordeling is nog geen doorgelopen beoordeling. Leg vast wie de uitkomst opvolgt en wanneer rechten daadwerkelijk zijn ingetrokken.' `
            -Source 'Entra ID - toegangsbeoordelingen' `
            -Metric ([PSCustomObject]@{ Value = $Active.Count; Total = $Reviews.Count; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'i3' -Article 'art. 21.2 i' -Source 'Entra ID - toegangsbeoordelingen' -ErrorRecord $_
    }

    # --- b5: unified audit log ------------------------------------------------------------------------
    try {
        $AuditConfig = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AdminAuditLogConfig' -Select 'UnifiedAuditLogIngestionEnabled'
        $AuditEnabled = $AuditConfig.UnifiedAuditLogIngestionEnabled -eq $true
        Add-CbwControl -ControlId 'b5' -Article 'art. 21.2 b' -Status ($(if ($AuditEnabled) { 'deels' } else { 'open' })) `
            -Headline ($(if ($AuditEnabled) { 'Het uniforme auditlogboek staat aan' } else { 'Het uniforme auditlogboek staat uit' })) `
            -Detail 'Aanstaan is de helft: de bewaartermijn bepaalt of u een incident van drie maanden geleden nog kunt reconstrueren. Standaard is dat 180 dagen, en zonder de juiste licentie niet langer.' `
            -Source 'Exchange Online - Get-AdminAuditLogConfig'
    } catch {
        Add-CbwUnknown -ControlId 'b5' -Article 'art. 21.2 b' -Source 'Exchange Online - Get-AdminAuditLogConfig' -ErrorRecord $_
    }

    # --- e4: applied CIPP standards -------------------------------------------------------------------
    try {
        $Standards = Get-CIPPStandards -TenantFilter $TenantFilter
        $Applied = @($Standards | Where-Object { $_.Settings -or $_.Standard })
        $Status = if ($Applied.Count -ge 10) { 'geregeld' } elseif ($Applied.Count -gt 0) { 'deels' } else { 'open' }
        Add-CbwControl -ControlId 'e4' -Article 'art. 21.2 e' -Status $Status `
            -Headline "$($Applied.Count) CIPP-standaarden toegepast op deze tenant" `
            -Detail 'Toegepaste standaarden zijn uw hardening-baseline, en meteen het bewijs ervan: CIPP legt per standaard vast wat is afgedwongen en wanneer.' `
            -Source 'CIPP - standaarden' `
            -Metric ([PSCustomObject]@{ Value = $Applied.Count; Total = $null; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'e4' -Article 'art. 21.2 e' -Source 'CIPP - standaarden' -ErrorRecord $_
    }

    # --- f2: secure score as a measurable indicator ---------------------------------------------------
    try {
        $SecureScore = Get-CIPPSecureScoreReport -TenantFilter $TenantFilter | Select-Object -First 1
        if ($SecureScore -and $null -ne $SecureScore.Percentage) {
            $Percentage = [math]::Round([double]$SecureScore.Percentage, 1)
            Add-CbwControl -ControlId 'f2' -Article 'art. 21.2 f' -Status (Get-CbwVerdict -Percentage $Percentage -Good 75 -Partial 50) `
                -Headline "Secure Score staat op $Percentage%" `
                -Detail 'Bruikbaar als trendindicator die u periodiek aan het bestuur laat zien. Het is geen Cbw-norm en op zichzelf geen bewijs van naleving.' `
                -Source 'Microsoft Secure Score' `
                -Metric ([PSCustomObject]@{ Value = $SecureScore.Score; Total = $SecureScore.MaxScore; Percentage = $Percentage })
        } else {
            Add-CbwUnknown -ControlId 'f2' -Article 'art. 21.2 f' -Source 'Microsoft Secure Score'
        }
    } catch {
        Add-CbwUnknown -ControlId 'f2' -Article 'art. 21.2 f' -Source 'Microsoft Secure Score' -ErrorRecord $_
    }

    # --- h3: legacy protocols and transport security --------------------------------------------------
    try {
        $OrgConfig = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-OrganizationConfig' -Select 'SmtpClientAuthenticationDisabled'
        $SmtpUit = $OrgConfig.SmtpClientAuthenticationDisabled -eq $true

        # Per-mailbox POP and IMAP survive an org-wide SMTP AUTH block, so they are counted separately.
        $PopImap = $null
        try {
            $Mailboxes = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-CASMailbox' -Select 'Identity,PopEnabled,ImapEnabled')
            $PopImap = @($Mailboxes | Where-Object { $_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true }).Count
        } catch {
            # Geen zicht op de postvakken: dan oordelen we alleen over SMTP AUTH en zeggen dat erbij.
        }

        $Status = if (-not $SmtpUit) { 'open' } elseif ($null -eq $PopImap) { 'deels' } elseif ($PopImap -eq 0) { 'geregeld' } else { 'deels' }
        $Kop = if (-not $SmtpUit) {
            'SMTP-authenticatie staat organisatiebreed aan'
        } elseif ($null -eq $PopImap) {
            'SMTP-authenticatie staat organisatiebreed uit; POP en IMAP niet gecontroleerd'
        } elseif ($PopImap -eq 0) {
            'SMTP-authenticatie uit, en geen postvak met POP of IMAP'
        } else {
            "SMTP-authenticatie uit, maar $PopImap postvak(ken) heeft nog POP of IMAP aan"
        }

        Add-CbwControl -ControlId 'h3' -Article 'art. 21.2 h' -Status $Status `
            -Headline $Kop `
            -Detail 'Verouderde protocollen omzeilen voorwaardelijke toegang en meervoudige authenticatie. Dit oordeel gaat over mail; TLS op websites en andere diensten toetst u apart.' `
            -Source 'Exchange Online - organisatie- en postvakinstellingen' `
            -Metric ([PSCustomObject]@{ Value = $PopImap; Total = $null; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'h3' -Article 'art. 21.2 h' -Source 'Exchange Online - organisatieinstellingen' -ErrorRecord $_
    }

    # --- g3: phishing simulations ---------------------------------------------------------------------
    try {
        $Simulaties = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/security/attackSimulation/simulations' -tenantid $TenantFilter)
        $Grens = (Get-Date).AddMonths(-12)
        $Recent = @($Simulaties | Where-Object {
                $Datum = $_.completionDateTime ?? $_.launchDateTime ?? $_.createdDateTime
                $Datum -and [datetime]$Datum -gt $Grens
            })

        $Status = if ($Recent.Count -ge 2) { 'geregeld' } elseif ($Recent.Count -eq 1) { 'deels' } else { 'open' }
        Add-CbwControl -ControlId 'g3' -Article 'art. 21.2 g' -Status $Status `
            -Headline "$($Recent.Count) phishingsimulatie(s) in de afgelopen twaalf maanden" `
            -Detail 'Een simulatie telt pas als er iets met de uitkomst gebeurt: wie erin trapte krijgt opvolging, en het resultaat gaat mee in de rapportage aan het bestuur.' `
            -Source 'Defender for Office 365 - aanvalssimulatietraining' `
            -Metric ([PSCustomObject]@{ Value = $Recent.Count; Total = $Simulaties.Count; Percentage = $null })
    } catch {
        Add-CbwUnknown -ControlId 'g3' -Article 'art. 21.2 g' -Source 'Defender for Office 365 - aanvalssimulatietraining' -ErrorRecord $_
    }

    # Controls that no amount of Graph will settle. Listed explicitly so a blank is never read as a pass.
    $NotDetectable = @(
        [PSCustomObject]@{ ControlId = 'c1'; Article = 'art. 21.2 c'; Reason = 'Of er back-ups buiten de tenant staan, is niet uit Microsoft 365 af te leiden. De prullenbak en bewaarbeleid van Microsoft 365 zijn geen back-up.' }
        [PSCustomObject]@{ ControlId = 'c2'; Article = 'art. 21.2 c'; Reason = 'Een geslaagde restoretest bestaat alleen als verslag. Leg datum, omvang en uitkomst vast.' }
        [PSCustomObject]@{ ControlId = 'd1'; Article = 'art. 21.2 d'; Reason = 'Het leveranciersregister staat buiten de tenant.' }
        [PSCustomObject]@{ ControlId = 'd4'; Article = 'art. 21.2 d'; Reason = 'Of leveranciers contractueel binnen 24 uur moeten melden, blijkt uit het contract, niet uit de tenant.' }
        [PSCustomObject]@{ ControlId = 'e3'; Article = 'art. 21.2 e'; Reason = 'Een gepubliceerd CVD-beleid staat op de website van de klant.' }
        [PSCustomObject]@{ ControlId = 'g1'; Article = 'art. 21.2 g'; Reason = 'Scholing van bestuurders is een wettelijke eis met een presentielijst als bewijs, niet een tenantinstelling.' }
        [PSCustomObject]@{ ControlId = 'g2'; Article = 'art. 21.2 g'; Reason = 'Deelname aan bewustwordingstraining wordt buiten de tenant geregistreerd, tenzij u daar een gekoppeld platform voor gebruikt.' }
        [PSCustomObject]@{ ControlId = 'j4'; Article = 'art. 21.2 j'; Reason = 'Een noodcommunicatiekanaal is per definitie onafhankelijk van deze tenant - anders werkt het niet als de tenant plat ligt.' }
    )

    return [PSCustomObject]@{
        TenantFilter  = $TenantFilter
        GeneratedAt   = (Get-Date).ToUniversalTime().ToString('o')
        Controls      = @($Controls)
        NotDetectable = @($NotDetectable)
        Summary       = [PSCustomObject]@{
            Checked  = @($Controls).Count
            Geregeld = @($Controls | Where-Object { $_.Status -eq 'geregeld' }).Count
            Deels    = @($Controls | Where-Object { $_.Status -eq 'deels' }).Count
            Open     = @($Controls | Where-Object { $_.Status -eq 'open' }).Count
            Onbekend = @($Controls | Where-Object { $_.Status -eq 'onbekend' }).Count
        }
    }
}
