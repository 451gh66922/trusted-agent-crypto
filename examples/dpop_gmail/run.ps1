#Requires -Version 5.1
<#
.SYNOPSIS
  Week-1 demo: Windows TPM (Platform Crypto Provider) + Google OAuth DPoP -> Gmail API.

.NOTES
  1. Copy credentials.example.json -> credentials.json and fill client_id / client_secret.
  2. In Google Cloud Console, Web client redirect URI must be exactly:
     http://127.0.0.1:8765/
  3. Add your Google account under Google Auth Platform -> Audience -> Test users.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CredsPath = Join-Path $ScriptDir "credentials.json"
$TokenPath = Join-Path $ScriptDir "tokens.json"
$KeyName = "tpm-dpop-gmail-demo"
$TokenEndpoint = "https://oauth2.googleapis.com/token"
$AuthEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
$GmailThreadsEndpoint = "https://gmail.googleapis.com/gmail/v1/users/me/threads?maxResults=5&labelIds=INBOX"
$ProviderName = "Microsoft Platform Crypto Provider"

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function ConvertFrom-Base64Url([string]$Text) {
    $padded = $Text.Replace("-", "+").Replace("_", "/")
    switch ($padded.Length % 4) {
        2 { $padded += "==" }
        3 { $padded += "=" }
    }
    [Convert]::FromBase64String($padded)
}

function Get-JsonText([object]$Obj) {
    return ($Obj | ConvertTo-Json -Compress -Depth 8)
}

function New-RandomBase64Url([int]$ByteCount = 32) {
    $bytes = New-Object byte[] $ByteCount
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ConvertTo-Base64Url $bytes
}

function Get-PkcePair {
    $verifier = New-RandomBase64Url 32
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $challenge = ConvertTo-Base64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    return @{ verifier = $verifier; challenge = $challenge }
}

function Get-OrCreateTpmKey([string]$Name) {
    $provider = New-Object System.Security.Cryptography.CngProvider($ProviderName)
    try {
        return [System.Security.Cryptography.CngKey]::Open($Name, $provider)
    }
    catch {
        Write-Host "Creating TPM-backed key '$Name' via $ProviderName ..."
        $params = New-Object System.Security.Cryptography.CngKeyCreationParameters
        $params.Provider = $provider
        $params.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
        $params.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
        $params.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
        return [System.Security.Cryptography.CngKey]::Create(
            [System.Security.Cryptography.CngAlgorithm]::ECDsaP256,
            $Name,
            $params
        )
    }
}

function Get-EcdsaJwk([System.Security.Cryptography.CngKey]$Key) {
    $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($Key)
    $p = $ecdsa.ExportParameters($false)
    return @{
        kty = "EC"
        crv = "P-256"
        x   = ConvertTo-Base64Url $p.Q.X
        y   = ConvertTo-Base64Url $p.Q.Y
    }
}

function New-DPoPProof {
    param(
        [System.Security.Cryptography.CngKey]$Key,
        [hashtable]$Jwk,
        [string]$Method,
        [string]$Uri,
        [string]$Jti,
        [string]$Nonce = $null
    )

    $header = @{
        typ = "dpop+jwt"
        alg = "ES256"
        jwk = $Jwk
    }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $payload = [ordered]@{
        jti = $Jti
        htm = $Method
        htu = $Uri
        iat = $now
    }
    if ($Nonce) {
        $payload.nonce = $Nonce
    }

    $headerPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes((Get-JsonText $header)))
    $payloadPart = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes((Get-JsonText $payload)))
    $signingInput = "$headerPart.$payloadPart"
    $signingBytes = [Text.Encoding]::ASCII.GetBytes($signingInput)

    # Windows PowerShell 5.1 (.NET Framework) has no DSASignatureFormat.
    # ECDsaCng.SignData already returns IEEE P1363 (r||s), which ES256 JWTs need.
    $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($Key)
    $signature = $ecdsa.SignData(
        $signingBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $sigPart = ConvertTo-Base64Url $signature
    return "$signingInput.$sigPart"
}

function Get-HeaderValue {
    param($Headers, [string]$Name)
    if (-not $Headers) { return $null }
    if ($Headers[$Name]) { return [string]$Headers[$Name] }
    foreach ($key in $Headers.Keys) {
        if ([string]$key -ieq $Name) {
            return [string]$Headers[$key]
        }
    }
    return $null
}

function Invoke-TokenRequest {
    param(
        [hashtable]$Body,
        [string]$DPoPProof
    )

    $form = ($Body.GetEnumerator() | ForEach-Object {
        "{0}={1}" -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value)
    }) -join "&"

    try {
        $response = Invoke-WebRequest `
            -Uri $TokenEndpoint `
            -Method POST `
            -Headers @{ DPoP = $DPoPProof } `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $form `
            -UseBasicParsing

        return @{
            Ok         = $true
            Body       = ($response.Content | ConvertFrom-Json)
            Nonce      = (Get-HeaderValue $response.Headers "DPoP-Nonce")
            StatusCode = [int]$response.StatusCode
            Error      = $null
        }
    }
    catch {
        $webResponse = $_.Exception.Response
        if (-not $webResponse) { throw }

        $statusCode = [int]$webResponse.StatusCode
        $reader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
        $raw = $reader.ReadToEnd()
        $reader.Close()

        $errorBody = $null
        try { $errorBody = $raw | ConvertFrom-Json } catch { $errorBody = @{ error = $raw } }

        $nonce = $null
        try { $nonce = Get-HeaderValue $webResponse.Headers "DPoP-Nonce" } catch { }

        return @{
            Ok         = $false
            Body       = $errorBody
            Nonce      = $nonce
            StatusCode = $statusCode
            Error      = [string]$errorBody.error
        }
    }
}

function Invoke-TokenRequestWithNonceRetry {
    param(
        [System.Security.Cryptography.CngKey]$Key,
        [hashtable]$Jwk,
        [hashtable]$Body,
        [string]$Nonce = $null,
        [int]$MaxAttempts = 3
    )

    $currentNonce = $Nonce
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $jti = New-RandomBase64Url 24
        $proof = New-DPoPProof `
            -Key $Key -Jwk $Jwk -Method "POST" -Uri $TokenEndpoint `
            -Jti $jti -Nonce $currentNonce

        $result = Invoke-TokenRequest -Body $Body -DPoPProof $proof
        if ($result.Ok) {
            return $result
        }

        # Google: auth-code nonce cannot be reused for refresh (workflow isolation).
        # Expected first refresh response is 400 use_dpop_nonce + fresh DPoP-Nonce.
        if ($result.Error -eq "use_dpop_nonce" -and $result.Nonce) {
            Write-Host "Got use_dpop_nonce (attempt $attempt); retrying with fresh DPoP-Nonce ..."
            $currentNonce = $result.Nonce
            continue
        }

        throw ("Token request failed HTTP {0}: {1}" -f $result.StatusCode, ($result.Body | ConvertTo-Json -Compress -Depth 5))
    }

    throw "Token request failed after $MaxAttempts DPoP nonce retries."
}

function Get-GmailHeaderValue {
    param($Payload, [string]$Name)
    if (-not $Payload -or -not $Payload.headers) { return $null }
    foreach ($h in $Payload.headers) {
        if ([string]$h.name -ieq $Name) {
            return [string]$h.value
        }
    }
    return $null
}

function Show-GmailThreadSummaries {
    param(
        [string]$AccessToken,
        [object[]]$Threads
    )

    $i = 0
    foreach ($t in $Threads) {
        $i++
        # format=metadata returns messages with headers; closest to Gmail conversation rows
        $detailUri = "https://gmail.googleapis.com/gmail/v1/users/me/threads/$($t.id)" +
            "?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date"
        $detail = Invoke-RestMethod `
            -Uri $detailUri `
            -Headers @{ Authorization = "Bearer $AccessToken" }

        $msgs = @($detail.messages)
        $count = $msgs.Count
        if ($count -lt 1) { continue }

        # Use the latest message in the thread for From/Subject/Date (like Gmail list row)
        $latest = $msgs[$count - 1]
        $from = Get-GmailHeaderValue $latest.payload "From"
        $subject = Get-GmailHeaderValue $latest.payload "Subject"
        $date = Get-GmailHeaderValue $latest.payload "Date"
        if (-not $from) { $from = "(unknown)" }
        if (-not $subject) { $subject = "(no subject)" }
        if (-not $date) { $date = "(unknown)" }

        $countLabel = if ($count -gt 1) { " ($count)" } else { "" }
        Write-Host ("  [{0}] thread: {1}{2}" -f $i, $t.id, $countLabel)
        Write-Host ("      From:    {0}" -f $from)
        Write-Host ("      Subject: {0}" -f $subject)
        Write-Host ("      Date:    {0}" -f $date)
        if ($count -gt 1) {
            $ids = ($msgs | ForEach-Object { $_.id }) -join ", "
            Write-Host ("      msgs:    {0}" -f $ids)
        }
    }
}

function Start-AuthCodeFlow {
    param(
        [hashtable]$Config,
        [hashtable]$Pkce
    )

    $state = New-RandomBase64Url 16
    $query = @{
        client_id = $Config.client_id
        redirect_uri = $Config.redirect_uri
        response_type = "code"
        scope = $Config.scope
        access_type = "offline"
        prompt = "consent"
        include_granted_scopes = "true"
        code_challenge = $Pkce.challenge
        code_challenge_method = "S256"
        state = $state
    }
    $authUrl = $AuthEndpoint + "?" + (($query.GetEnumerator() | ForEach-Object {
        "{0}={1}" -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value)
    }) -join "&")

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Config.redirect_uri)
    $listener.Start()
    Write-Host "Listening on $($Config.redirect_uri)"
    Write-Host "Opening browser for Google consent ..."
    Start-Process $authUrl

    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response
    $code = $request.QueryString["code"]
    $returnedState = $request.QueryString["state"]
    $oauthError = $request.QueryString["error"]

    $html = if ($oauthError) {
        "<html><body><h3>Authorization failed: $oauthError</h3><p>You can close this tab.</p></body></html>"
    }
    else {
        "<html><body><h3>Authorization succeeded.</h3><p>You can close this tab and return to PowerShell.</p></body></html>"
    }
    $buffer = [Text.Encoding]::UTF8.GetBytes($html)
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()
    $listener.Stop()

    if ($oauthError) {
        throw "OAuth authorization failed: $oauthError"
    }
    if ($returnedState -ne $state) {
        throw "OAuth state mismatch."
    }
    if (-not $code) {
        throw "No authorization code returned."
    }
    return $code
}

if (-not (Test-Path $CredsPath)) {
    throw "Missing $CredsPath. Copy credentials.example.json and fill in client_id/client_secret."
}

$configRaw = Get-Content $CredsPath -Raw | ConvertFrom-Json
$required = @("client_id", "client_secret", "redirect_uri", "scope")
foreach ($name in $required) {
    if (-not $configRaw.$name) {
        throw "credentials.json missing '$name'."
    }
}
$config = @{
    client_id     = [string]$configRaw.client_id
    client_secret = [string]$configRaw.client_secret
    redirect_uri  = [string]$configRaw.redirect_uri
    scope         = [string]$configRaw.scope
}

Write-Host "=== Step 1: TPM key ==="
$key = Get-OrCreateTpmKey $KeyName
$jwk = Get-EcdsaJwk $key
Write-Host "TPM key ready: $KeyName"
Write-Host "Public JWK x=$($jwk.x.Substring(0, 12))..."

Write-Host "`n=== Step 2: Browser authorization ==="
$pkce = Get-PkcePair
$authCode = Start-AuthCodeFlow -Config $config -Pkce $pkce

Write-Host "`n=== Step 3: Exchange code with DPoP ==="
$jti = ConvertTo-Base64Url ([System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($authCode)))
$proof = New-DPoPProof -Key $key -Jwk $jwk -Method "POST" -Uri $TokenEndpoint -Jti $jti
$tokenBody = @{
    grant_type = "authorization_code"
    code = $authCode
    redirect_uri = $config.redirect_uri
    client_id = $config.client_id
    client_secret = $config.client_secret
    code_verifier = $pkce.verifier
}
$result = Invoke-TokenRequest -Body $tokenBody -DPoPProof $proof
if (-not $result.Ok) {
    throw ("Token exchange failed HTTP {0}: {1}" -f $result.StatusCode, ($result.Body | ConvertTo-Json -Compress -Depth 5))
}
$tokens = $result.Body
$dpopNonce = $result.Nonce

if (-not $tokens.access_token) {
    throw "Token exchange failed: $($tokens | ConvertTo-Json -Depth 5)"
}

Write-Host "Access token received."
if ($tokens.refresh_token) {
    Write-Host "Refresh token received (DPoP-bound)."
}
else {
    Write-Warning "No refresh_token returned. Re-run with prompt=consent or revoke app access and retry."
}

@{
    access_token = $tokens.access_token
    refresh_token = $tokens.refresh_token
    expires_in = $tokens.expires_in
    dpop_nonce = $dpopNonce
    obtained_at = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json | Set-Content -Path $TokenPath -Encoding UTF8

Write-Host "`n=== Step 4: Call Gmail API (by thread / conversation) ==="
$gmail = Invoke-RestMethod `
    -Uri $GmailThreadsEndpoint `
    -Headers @{ Authorization = "Bearer $($tokens.access_token)" }
Write-Host "Gmail threads returned (estimate): $($gmail.resultSizeEstimate)"
if ($gmail.threads) {
    Show-GmailThreadSummaries -AccessToken $tokens.access_token -Threads $gmail.threads
}
else {
    Write-Host "  (no threads in this page)"
}

if ($tokens.refresh_token) {
    Write-Host "`n=== Step 5: Refresh with DPoP + nonce (optional demo) ==="
    Write-Host "Note: Google isolates nonce namespaces between auth-code and refresh;"
    Write-Host "      first refresh often returns 400 use_dpop_nonce — that is expected, then we retry."
    $refreshBody = @{
        grant_type = "refresh_token"
        refresh_token = $tokens.refresh_token
        client_id = $config.client_id
        client_secret = $config.client_secret
    }
    # Seed with Step-3 nonce if present; Google usually rejects it once and issues a refresh-workflow nonce.
    $refreshResult = Invoke-TokenRequestWithNonceRetry `
        -Key $key -Jwk $jwk -Body $refreshBody -Nonce $dpopNonce
    Write-Host "Refresh succeeded. New access token prefix: $($refreshResult.Body.access_token.Substring(0, 16))..."
}

Write-Host "`nDone."
Write-Host "Saved tokens to: $TokenPath"
Write-Host "Mechanism: private key stays in TPM; Google binds refresh token to this public key via DPoP."
