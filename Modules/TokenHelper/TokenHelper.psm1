function Get-ArmToken {

    Param
    (
        [Parameter(Mandatory = $true)]
        $ArmEndpoint,
        [Parameter(Mandatory = $false)]
        $TenantId = 'Common',
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Username,
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Password,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $AppId,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        $AppSecret,
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $Cert,
        [Parameter(Mandatory = $true, ParameterSetName = "RefreshToken")]
        $RefreshToken
    )

    $metadataEndpoint = "{0}/metadata/endpoints?api-version=2015-01-01" -f $ArmEndpoint
    $armMetedata = Invoke-RestMethod -Uri $metadataEndpoint
    $loginEndpoint = $armMetedata.authentication.loginEndpoint
    if ($loginEndpoint -like '*/adfs') {
        $adMetadataUri = "{0}/.well-known/openid-configuration" -f $loginEndpoint
    }
    else {
        $adMetadataUri = "{0}/{1}/.well-known/openid-configuration" -f $loginEndpoint, $TenantId
    }
    $adMetadata = Invoke-RestMethod -Uri $adMetadataUri
    $tokenEndpoint = $adMetadata.token_endpoint
    $params = $PSBoundParameters
    $params.Remove('ArmEndpoint') | Out-Null
    $params.Remove('TenantId') | Out-Null
    $params.Add('Resource', $armMetedata.authentication.audiences[0])
    $params.Add('TokenEndpoint', $tokenEndpoint)
    $token = Get-ResourceToken @params
    $token
}

Export-ModuleMember -Function Get-ArmToken

function Get-GraphToken {

    Param
    (
        [Parameter(Mandatory = $true)]
        $ArmEndpoint,
        [Parameter(Mandatory = $false)]
        $TenantId = 'Common',
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Username,
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Password,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $AppId,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        $AppSecret,
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $Cert,
        [Parameter(Mandatory = $true, ParameterSetName = "RefreshToken")]
        $RefreshToken
    )

    $metadataEndpoint = "{0}/metadata/endpoints?api-version=2015-01-01" -f $ArmEndpoint
    $armMetedata = Invoke-RestMethod -Uri $metadataEndpoint
    $loginEndpoint = $armMetedata.authentication.loginEndpoint
    if ($loginEndpoint -like '*/adfs') {
        $adMetadataUri = "{0}/.well-known/openid-configuration" -f $loginEndpoint
    }
    else {
        $adMetadataUri = "{0}/{1}/.well-known/openid-configuration" -f $loginEndpoint, $TenantId
    }
    $adMetadata = Invoke-RestMethod -Uri $adMetadataUri
    $tokenEndpoint = $adMetadata.token_endpoint
    $params = $PSBoundParameters
    $params.Remove('ArmEndpoint') | Out-Null
    $params.Remove('TenantId') | Out-Null
    $params.Add('Resource', $armMetedata.graphEndpoint)
    $params.Add('TokenEndpoint', $tokenEndpoint)
    $token = Get-ResourceToken @params
    $token
}

Export-ModuleMember -Function Get-GraphToken

function Get-ResourceToken {
    Param
    (
        [Parameter(Mandatory = $true)]
        $Resource,
        [parameter(Mandatory = $true)]
        $TokenEndpoint,
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Username,
        [Parameter(Mandatory = $true, ParameterSetName = "UserName")]
        $Password,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $AppId,
        [Parameter(Mandatory = $true, ParameterSetName = "SecretSP")]
        $AppSecret,
        [Parameter(Mandatory = $true, ParameterSetName = "CertSP")]
        $Cert,
        [Parameter(Mandatory = $true, ParameterSetName = "RefreshToken")]
        $RefreshToken
    )


    switch ($PsCmdlet.ParameterSetName) {
        "UserName" {
            #using a username and password
            $psClientID = '1950a258-227b-4e31-a9cf-717495945fc2'
            $grantBody = 'grant_type=password&scope=openid&resource={0}&client_id={1}&username={2}&password={3}' -f $Resource, $psClientID, $Username, $Password
        }
        "SecretSP" {
            #using a secret based service principal
            $grantBody = 'grant_type=client_credentials&resource={0}&client_id={1}&client_secret={2}' -f $Resource, $AppId, $AppSecret
        }
        "CertSP" {
            #Using a certificate based service principal
            $jwt = New-SelfSignedJsonWebToken -ClientCertificate $Cert -ClientId $AppId -Audience $adMetadata.token_endpoint 
            $grantBody = 'grant_type=client_credentials&resource={0}&client_id={1}&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={2}' -f $Resource, $AppId, $jwt
        }
        "RefreshToken" {
            #using a refresh token
            $grantBody = "grant_type=refresh_token&refresh_token={0}&resource={1}" -f $RefreshToken, $Resource
        }
    }
      
    $tokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -ContentType "application/x-www-form-urlencoded" -Body $grantBody -Method Post 
    $tokenResponse
}

Export-ModuleMember -Function Get-ResourceToken

function New-SelfSignedJsonWebToken {

    param
    (
        # The client certificate used to sign the token.
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,

        # The client ID (appId) for the token.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId,

        # The target audience for the token.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Audience,

        # The number of seconds relative to the current UTC datetime before which the token will be invalid. Default is -90 (90 seconds ago from 'now').
        [Parameter()]
        [int] $NotBeforeSecondsRelativeToNow = -90,

        # The number of seconds relative to the current UTC datetime until which the token will be valid. Default is 3600 (one hour from 'now').
        [Parameter()]
        [int] $ExpirationSecondsRelativeToNow = 3600
    )

    function ConvertTo-Base64UrlEncode([byte[]]$bytes) { [System.Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').Trim('=') }

    $tokenHeaders = [ordered]@{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-Base64UrlEncode $ClientCertificate.GetCertHash()
    }

    $currentUtcDateTimeInSeconds = ([datetime]::UtcNow - [datetime]'1970-01-01 00:00:00').TotalSeconds

    $tokenClaims = [ordered]@{
        aud = $Audience
        exp = [long]($currentUtcDateTimeInSeconds + $ExpirationSecondsRelativeToNow)
        iss = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = [long]($currentUtcDateTimeInSeconds + $NotBeforeSecondsRelativeToNow)
        sub = $ClientId
    }


    # Note - we escape the forward slashes ('/') as the ConvertTo-Json cmdlet does not. This may not actually be necessary.
    $tokenParts = @()
    $tokenParts += ConvertTo-Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $tokenHeaders -Depth 10 -Compress).Replace('/', '\/')))
    $tokenParts += ConvertTo-Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $tokenClaims -Depth 10 -Compress).Replace('/', '\/')))
    
    try {
        $csp = New-Object System.Security.Cryptography.CspParameters(
            ($providerType = 24),
            ($providerName = 'Microsoft Enhanced RSA and AES Cryptographic Provider'),
            $ClientCertificate.PrivateKey.CspKeyContainerInfo.KeyContainerName)
        $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore

        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
        $rsa.ImportParameters($ClientCertificate.PrivateKey.ExportParameters($true))
        $hashAlg = [System.Security.Cryptography.SHA256]::Create()

        $datatosign = [System.Text.Encoding]::UTF8.GetBytes($tokenParts -join '.')
        $signatureBytes = $rsa.SignData($datatosign, $hashAlg)
        $rsa.Dispose()
        $hashAlg.Dispose()

        $tokenParts += ConvertTo-Base64UrlEncode $signatureBytes
    }
    finally {
        $hashAlg.Dispose()
        $rsa.Dispose()
        }
    }

    return ($tokenParts -join '.')
}