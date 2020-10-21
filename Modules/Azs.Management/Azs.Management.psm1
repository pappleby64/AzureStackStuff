#Requires -Modules @{ ModuleName="Az.Accounts"; ModuleVersion="2.0" }

Import-LocalizedData LocalizedText -Filename Azs.Management.Strings.psd1 -ErrorAction SilentlyContinue

$settingsFolder = "$env:LOCALAPPDATA\AzsStampHelper"
$settingsFile = "$settingsFolder\StampDef.json"


if (!(Test-Path $settingsFolder)) {
    New-Item -ItemType Directory $settingsFolder | Out-Null
}

if (Test-Path $settingsFile) {
    $StampDef = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
}
else {
    $stamps = @()
    $StampDef = [PSCustomObject]@{
        "Stamps" = $stamps
    }
}

Function ValidateStampName {
    Param
    (
        [string]
        $stamp
    )
    if ($StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }) {
        $true
    }
    else {
        throw "Unkown Stamp, Use Get-Stamp to list available stamps"
    }
}

Function GetEnvironment {
    Param
    (
        [Parameter (Mandatory = $true)]
        $Stamp,
        [Switch]
        $Tenant
    )

    if ($Tenant) {
        $envName = '{0}-Tenant' -f $Stamp.Name
        $url = 'https://management.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
        $kvdns = 'vault.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
        $kvresourceId = 'https://vault.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain

    }
    else {
        $envName = '{0}-Admin' -f $Stamp.Name
        $url = 'https://adminmanagement.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
        $kvdns = 'adminvault.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
        $kvresourceId = 'https://adminvault.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
    }

    $azEnv = Get-AzEnvironment -Name $envName 
    if (!$azEnv) {
        Write-Verbose "Adding new AzEnvironment $envName for endpoint $url"
        $azEnv = Add-AzEnvironment -Name $envName -ArmEndpoint $url -ErrorAction SilentlyContinue
        Set-AzEnvironment -Name $envName -AzureKeyVaultDnsSuffix $kvdns -AzureKeyVaultServiceEndpointResourceId $kvresourceId | out-null
    }

    if (!$azEnv) {
        throw "Unable to create Azure Environment"
    }
    $azEnv
}

Function GetKeyVaultSecret {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $valultName,
        [Parameter(Mandatory = $true)]
        [string]
        $SecretName
    )

    $kvContext = GetKeyVaultContext
    if (!$kvContext) {
        Write-Error  $localizedText.NoAzureContext
        return
    }
    $kvsecret = Get-AzKeyVaultSecret -VaultName $valultName -Name $secretName -DefaultProfile $kvContext -ErrorAction SilentlyContinue

    $kvsecret
}

function GetUserCredential {
    param
    (
        $user
    )
     
    $password = (GetKeyVaultSecret -valultName $user.VaultName -SecretName $user.SecretName ).SecretValue
    if ($password) {
        $cred = New-Object System.Management.Automation.PSCredential $user.UserName, $Password 
    }
    $cred
}

Function ConnectAzureStackUser {
    Param
    (
        $User,
        $Environment
    )

    $accountParams = @{ }
    $accountParams.Add('Environment', $Environment)

    if (![String]::IsNullOrEmpty($User.VaultName) -and ![String]::IsNullOrEmpty($User.SecretName)) {
        $cred = GetUserCredential -user $User
        if ($cred) { $accountParams.Add('Credential', $cred) }
    }

    if (![String]::IsNullOrEmpty($User.TenantId)) {
        Write-Verbose "Adding tenantId $($user.TenantId)"
        $accountParams.Add('Tenant', $User.TenantId)
    }

    if (![String]::IsNullOrEmpty($User.Subscription)) {
        Write-Verbose "Adding Subscription $($User.Subscription)"
        $accountParams.Add('Subscription', $User.Subscription)
    }

    if (!$cred) {
        Write-Host ("$($localizedText.LogonToEnv)" -f $Environment.Name)
        Read-Host "Press Enter to continue" | Out-Null
    }
    $result = Connect-AzAccount @accountParams -SkipContextPopulation -ContextName $Environment
    $result.Context 
}

Function Prompt {
    Write-Host -ForegroundColor Cyan -NoNewline "[$((Get-AzContext).Environment.Name)]"
    Write-Host -NoNewline "$(Get-Location)"
    return "> "
}

Function GetKeyVaultContext {
    $ctx = Get-AzContext -ListAvailable | Where-Object { $_.Name -eq 'KeyVaultContext' }
    if (!$ctx) {
        Write-Host $localizedText.KeyvaultLogon
        Read-Host "Press Enter to continue" | Out-Null
        $cloud = $StampDef.KeyVaultCloud.Cloud
        if ([string]::IsNullOrEmpty($cloud)) { $cloud = 'AzureCloud' }
        $tenant = $StampDef.KeyVaultCloud.TenantId
        $sub = $StampDef.KeyVaultCloud.Subscription

        $AccountParams = @{ }
        if (-not [string]::IsNullOrEmpty($cloud)) { $AccountParams.Add("EnvironmentName", $cloud) }
        if (-not [string]::IsNullOrEmpty($tenant)) { $AccountParams.Add("Tenant", $tenant) }
        if (-not [string]::IsNullOrEmpty($sub)) { $AccountParams.Add("Subscription", $sub) }
        $result = Connect-AzAccount @AccountParams -SkipContextPopulation -ContextName 'KeyVaultContext'      
        $ctx = $result.Context
    }
    $ctx
}

Function Connect-AzureStack {
    <#
    .SYNOPSIS
        Connects to the  Azure Stack HUb ARM endpoint
    .DESCRIPTION
        Connects to the Azure Stack Hub ARM endpoint, By default connects to Admin Arm endpooint. 
        Use -Tenant to connect to tenant Arm enspoint
    .EXAMPLE
        PS C:\> Connect-AzureStack -Stamp MyStamp 
        PS C:\> Connect-AzureStack -Stamp MyStamp -Tenant
    .NOTES
        Will use a credential from Key Valult if available and defined in the stamp settings
#>
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Switch]
        $Tenant
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }

    if ($Tenant) {
        $azEnv = GetEnvironment -Stamp $stampInfo -Tenant
        $user = $stampInfo.TenantUser
    }
    else {
        $azEnv = GetEnvironment -Stamp $stampInfo 
        $user = $stampInfo.AdminUser
    }
    Write-Verbose "Connecting to Environment $($azEnv.Name) with user account $($user.userName)"
    $ctx = Get-AzContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $azEnv.Name }
    if ($ctx) {
        Write-Verbose  "Using existing AzContext for user $($ctx.Account.Id)"
        $ctx | Select-AzContext | Out-Null
    }
    else {
        Write-Verbose "No exiting context found, creating context"
        $ctx = ConnectAzureStackUser -User $user -Environment $azEnv
    }
    if ($ctx.Environment.Name -eq $azEnv.Name -and $ctx.Account.Id -eq $user.UserName) {
        Write-Verbose  "Succesfully connected to $($azEnv.Name) as $($user.UserName)"
    }
}

Function Connect-AzureStackPortal {
    <#
    .SYNOPSIS
        Connects to the  Azure Stack HUb Portal
    .DESCRIPTION
        Connects to the Azure Stack Hub Portal, By default connects to Admin Portal. 
        Use -Tenant to connect to Tenant Portal
    .EXAMPLE
        PS C:\> Connect-AzureStackPortal -Stamp MyStamp 
        PS C:\> Connect-AzureStackPortal -Stamp MyStamp -Tenant
    .NOTES
        Will use a credential from Key Valult if available and defined in the stamp settings
        The password will be placed on teh clipboard
#>
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Switch]
        $Tenant

    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }

    if ($Tenant) {
        $user = $stampInfo.TenantUser
        $url = 'https://portal.{0}.{1}/{2}' -f $stampInfo.Region, $stampInfo.ExternalFqdnDomain, $user.TenantId
    }
    else {
        $user = $stampInfo.AdminUser
        $url = 'https://adminportal.{0}.{1}/{2}' -f $stampInfo.Region, $stampInfo.ExternalFqdnDomain, $user.TenantId
    }
    Write-Verbose "Opening browser to Portal $url"
    if (![String]::IsNullOrEmpty($User.VaultName) -and ![String]::IsNullOrEmpty($User.SecretName)) {
        Write-Verbose "Retrieveing password for $($user.UserName) from keyvault"
        (GetKeyVaultSecret -valultName $user.VaultName -secretName $user.SecretName ).SecretValueText | clip.exe
        Write-Host -ForegroundColor Cyan "Login using account $($user.UserName) The password is on the clipboard"
        Write-Host -ForegroundColor Cyan "Press enter to launch $Browser"
        Read-Host | Out-Null
    }
    Start-Process -FilePath  $url
}

Function Connect-PepSession {
    <#
    .SYNOPSIS
        Connects to the  Azure Stack Privileged Endpoint
    .DESCRIPTION
        Connects to the Azure Stack Hub Privileged Endpoint. Connect-PepSession will use an existing session if available.
    .EXAMPLE
        PS C:\> Connect-PepSession -Stamp MyStamp 
    .NOTES
        Will use a credential from Key Valult if available and defined in the stamp settings.
#>    
    [Alias("Get-PepSession")]
    Param
    (
        [Parameter(Mandatory = $true, position = 0)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $false, ParameterSetName = 'SessionName')]
        [string]
        $SessionName,
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'ERCS01',
            'ERCS02',
            'ERCS03'
        )]
        [String]
        $ErcsVM,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $PepCredential,
        [Switch]
        $Force     
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    $pepUser = $stampInfo.CloudAdminUser
    Write-Verbose "Connecting to pep on environment $stamp with user $($pepUSer.UserName)"
    
    if ($PSCmdlet.ParameterSetName -ne 'SessionName') {

        if (![String]::IsNullOrEmpty($ErcsVM)) {
            switch ($ErcsVM) {
                'ERCS01' { $ercsIpList = $stampInfo.ErcsVMs[0] }
                'ERCS02' { $ercsIpList = $stampInfo.ErcsVMs[1] }
                'ERCS03' { $ercsIpList = $stampInfo.ErcsVMs[2] }
            }
        }
        else {
            $ercsIpList = $stampInfo.ErcsVMs
            Write-Verbose "Using following list of IP addresses $ercsIpList"
        }    
     
        Write-Verbose "Checking WinRm running and configured"
        if ((get-service -Name WinRm).Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Host $LocalizedText.WinRmNotRunning
            return  
        }
    
        [Security.Principal.WindowsPrincipal]$id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Verbose "Current user running as admin $isAdmin"
        if ($Force -and ($isAdmin -eq $false )) {
            Write-Host $LocalizedText.ForceAdmin
            return
        }

        $currentTrustedHostsValue = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        Write-Verbose "Current Trusted Host Value $currentTrustedHostsValue"
        $hostlist = @()
        if (-not [String]::IsNullOrEmpty($currentTrustedHostsValue)) {
            $hostlist += $currentTrustedHostsValue.split(',')
        }

        $hostpresent = $true
        $wildcard = ($hostlist -contains '*')
        $ercsIpList | ForEach-Object { if ($hostlist -notcontains $_) { $hostpresent = $false } }
        if (-not ($wildcard -or $hostpresent)) {
            Write-Verbose "Trusted Hosts does not include wildcard or required IP addresses"
            if ($Force -and $isAdmin) {
                $hostlist += $ercsIpList
                $newlist = ($hostlist | Sort-Object -Unique) -join ","
                Write-Verbose "new Value for TrustedHosts is $newlist"
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newlist -Confirm:$false -Force
            }
            else {
                Write-Host $LocalizedText.TrustedHost
                return
            }
        }
        
        Write-Verbose "Checking for existing open session"
        $session = Get-PSSession | Where-Object { $_.ComputerName -in $ercsIpList -and $_.State -eq 'Opened' } | Sort-Object Id -Descending | Select-Object -First 1
                       
        if (!$session) {
            $pepCred = $null
            Write-Verbose "No open connections found, createing new one"
            if (![String]::IsNullOrEmpty($pepUser.VaultName) -and ![String]::IsNullOrEmpty($pepUser.SecretName)) {
                Write-Verbose "Retrieving credential from key vault"
                $pepPassword = GetKeyVaultSecret -valultName $pepUser.VaultName -secretName $pepUser.SecretName -ErrorAction SilentlyContinue
                if ($pepPassword) {
                    $pepCred = New-Object System.Management.Automation.PSCredential $pepUser.UserName, $pepPassword.secretValue
                }
            }
            else {
                if ($PepCredential) {
                    $pepCred = $PepCredential
                }
                else {
                    Write-Host ("$($localizedText.LogonPep)" -f $Stamp)
                    Read-Host "Press Enter to continue" | Out-Null
                    $pepCred = Get-Credential -Message "Enter PEP credentials" -UserName $pepUser.userName
                }
            }
            $sessionName = "{0}{1}" -f $Stamp, (Get-Date).ToString('HHmm')
            $usCulture = New-PSSessionOption -Culture en-US -UICulture en-US
            foreach ($pepip in $ercsIpList) { 
                Write-Host "Creating PEP session on $Stamp using IP $pepip"
                $session = New-PSSession -ComputerName $pepip -ConfigurationName PrivilegedEndPoint -Credential $pepCred -Name $sessionName -SessionOption $usCulture -ErrorAction Continue
                if ($session) {
                    break
                }
            }
        }
        if (!$session) {
            Write-Error "Failed to create PEP session"
        }
    }
    else {
        $pepPassword = (GetKeyVaultSecret -valultName $pepUser.VaultName -secretName $pepUser.SecretName).SecretValue
        $pepCred = New-Object System.Management.Automation.PSCredential $pepUser.UserName, $pepPassword
        $session = Get-PSSession -ComputerName $stampInfo.ErcsVMs -Credential $pepCred -Name $SessionName
        if ($session) {
            $session | Connect-PSSession | Out-Null
        }
    }
    return $session
}

Function Enter-PepSession {
    Param
    (
        [Parameter(Mandatory = $true, position = 0)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'ERCS01',
            'ERCS02',
            'ERCS03'
        )]
        [String]
        $ErcsVM,
        [System.Management.Automation.PSCredential]
        $PepCredential     
    )
    $session = Connect-PepSession @PSBoundParameters
    if ($session) {
        Enter-PSSession -Session $session
    }
}

Function Unlock-PepSession {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp
    )

    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        $token = Invoke-Command -Session $pep { Get-supportSessionToken } 
        Write-Host $token
        Set-Clipboard -Value $token 
        Write-Host -ForegroundColor Cyan "The support Session token has been copied to the clipboard"
        Write-Host -ForegroundColor Cyan "Make sure the token returned from support is on the clipboard then press return to unlock the session"
        Read-Host | Out-Null
        $token = Get-Clipboard -Format Text | Out-String
        Invoke-Command -Session $pep { Unlock-supportSession -ResponseToken $using:token }    
        $pep
    }
}

Function Close-PepSession {
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Single', position = 0)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [Switch]
        $All
    )
    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
        $session = Get-PSSession | Where-Object { $_.ComputerName -in $stampInfo.ErcsVMs -and $_.State -ne 'Disconnected' } 
        if ($session) {
            $session | Remove-PSSession
        }
    }
    else {
        Get-PSSession | Where-Object { $_.ConfigurationName -eq 'PrivilegedEndPoint' } | Remove-PSSession
    }
}

Function Save-PepSession {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    $session = Get-PSSession | Where-Object { $_.ComputerName -in $stampInfo.ErcsVMs } 
    if ($session) {
        Write-Host -ForegroundColor Cyan "Session $($Session.Name) saved"
        $session | Disconnect-PSSession 
    }
}

Function Clear-StampCache {
    foreach ($stamp in $StampDef.Stamps) {
        $ctx = Get-AzContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -like "$($Stamp.Name)-*" }
        $ctx | Remove-AzContext -Force
        $env = Get-AzEnvironment | Where-Object { $_.Name -like "$($Stamp.Name)-*" }
        $env | Remove-AzEnvironment | Out-Null
    }
}

Function Get-Stamp {
    Param
    (
        [Parameter(Mandatory = $false, position = 0)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp     
    )
    if ($stamp) {
        $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    }
    else {
        $StampDef.Stamps
    }
}

Function Add-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        [Parameter(Mandatory = $true, ParameterSetName = "region")]
        [string]
        $Region,
        [Parameter(Mandatory = $true, ParameterSetName = "region")]
        [string]
        $Fqdn,
        [Parameter(Mandatory = $true, ParameterSetName = "regionfqdn")]
        [string]
        $ReqionFqdn,
        [Parameter(Mandatory = $true, ParameterSetName = "stampInfo")]
        [string]
        $StampInfoJson,
        [Parameter(Mandatory = $true, ParameterSetName = "regionfqdn")]
        [Parameter(Mandatory = $true, ParameterSetName = "region")]
        [string[]]
        $ErcsVm,
        [string]
        $AdminUserName,
        [string]
        $AdminUserTenantid,
        [string]
        $AdminUserVaultName,
        [string]
        $AdminUserSecretName,
        [string]
        $TenantUserName,
        [string]
        $TenantUserTenantid,
        [string]
        $TenantUserVaultName,
        [string]
        $TenantUserSecretName,
        [string]
        $TenantUserSubscription,
        [string]
        $CloudAdminUserName,
        [string]
        $CloudAdminVaultName,
        [string]
        $CloudAdminSecretName
    )

    if ($StampDef.Stamps | Where-Object { $_.Name -eq $Name }) {
        Write-Host "Stamp $Name already exists"
        return
    }

    $adminUser = [PSCustomObject]@{
        "UserName"     = $AdminUserName
        "TenantId"     = $AdminUserTenantid
        "VaultName"    = $AdminUserVaultName
        "SecretName"   = $AdminUserSecretName
        "Subscription" = 'Default Provider Subscription'
    }
    $TenantUser = [PSCustomObject]@{
        "UserName"     = $TenantUserName
        "TenantId"     = $TenantUserTenantid
        "VaultName"    = $TenantUserVaultName
        "SecretName"   = $TenantUserSecretName
        "Subscription" = $TenantUserSubscription
    }
    $CloudAdminUser = [PSCustomObject]@{
        "UserName"   = $CloudAdminUserName
        "VaultName"  = $CloudAdminVaultName
        "SecretName" = $CloudAdminSecretName
    }
    if ($reqionfqdn) {
        $split = $reqionfqdn.Split('.')
        $Region = $split[0]
        $Fqdn = $split[1..-1] -join '.'
    }
    if ($StampInfoJson) {
        try {
            $stampInfo = ConvertFrom-Json -InputObject (Get-Content -Path $StampInfoJson -raw) -ErrorAction  SilentlyContinue
        }
        catch {
        }
        if (![string]::IsNullOrEmpty($stampInfo)) {
            $ercsVm = $stampinfo.EmergencyConsoleIPAddresses
            $Region = $stampInfo.RegionName
            $split = $stampInfo.ExternalDomainFQDN.Split('.')
            $Region = $split[0]
            $Fqdn = $split[1..$split.count] -join '.'
            $CloudAdminUser.UserName = "{0}\CloudAdmin" -f $stampInfo.DomainNetBIOSName
        }
        else {
            Write-Error "StampInfo Json file not valid or missing"
            return 
        }
    }
    $newStamp = [PSCustomObject]@{
        "Name"               = $Name
        "Region"             = $Region
        "ExternalFqdnDomain" = $fqdn
        "ErcsVMs"            = $ercsVm
        "AdminUser"          = $adminUser
        "TenantUser"         = $TenantUser
        "CloudAdminUser"     = $CloudAdminUser
    }
    [System.Collections.ArrayList]$ArrayList = @()
    $StampDef.Stamps | ForEach-Object { $ArrayList += $_ }
    $ArrayList += $newStamp
    $script:StampDef.Stamps = $ArrayList
    ConvertTo-Json -InputObject $StampDef -Depth 99 | Out-File $settingsFile -Encoding utf8
}

Function Set-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Name,
        [string]
        $AdminUserName,
        [string]
        $AdminUserTenantid,
        [string]
        $AdminUserVaultName,
        [string]
        $AdminUserSecretName,
        [string]
        $TenantUserName,
        [string]
        $TenantUserTenantid,
        [string]
        $TenantUserSubscription,
        [string]
        $TenantUserVaultName,
        [string]
        $TenantUserSecretName,
        [string]
        $CloudAdminUserName,
        [string]
        $CloudAdminVaultName,
        [string]
        $CloudAdminSecretName
    )
    $stamp = $StampDef.Stamps | Where-Object { $_.Name -eq $Name }

    if ($PSBoundParameters.Keys -contains "AdminUserName") { $stamp.AdminUser.UserName = $AdminUserName }
    if ($PSBoundParameters.Keys -contains "AdminUserTenantid") { $stamp.AdminUser.TenantId = $AdminUserTenantid }
    if ($PSBoundParameters.Keys -contains "AdminUserVaultName") { $stamp.AdminUser.VaultName = $AdminUserVaultName }
    if ($PSBoundParameters.Keys -contains "AdminUserSecretName") { $stamp.AdminUser.SecretName = $AdminUserSecretName }

    if ($PSBoundParameters.Keys -contains "TenantUserName") { $stamp.TenantUser.UserName = $TenantUserName }
    if ($PSBoundParameters.Keys -contains "TenantUserTenantid") { $stamp.TenantUser.TenantId = $TenantUserTenantid }
    if ($PSBoundParameters.Keys -contains "TenantUserSubscription") { $stamp.TenantUser.Subscription = $TenantUserSubscription }
    if ($PSBoundParameters.Keys -contains "TenantUserVaultName") { $stamp.TenantUser.VaultName = $TenantUserVaultName }
    if ($PSBoundParameters.Keys -contains "TenantUserSecretName") { $stamp.TenantUser.SecretName = $TenantUserSecretName }

    if ($PSBoundParameters.Keys -contains "CloudAdminUserName") { $stamp.CloudAdminUser.UserName = $CloudAdminUserName }
    if ($PSBoundParameters.Keys -contains "CloudAdminVaultName") { $stamp.CloudAdminUser.VaultName = $CloudAdminVaultName }
    if ($PSBoundParameters.Keys -contains "CloudAdminSecretName") { $stamp.CloudAdminUser.SecretName = $CloudAdminSecretName }

    ConvertTo-Json -InputObject $StampDef -Depth 99 | Out-File $settingsFile -Encoding utf8
}

Function Remove-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Name
    )
    $stamps = $StampDef.Stamps | Where-Object { $_.Name -ne $Name }
    if ($stamps.count -eq 0) {
        $stamps = @()
    }
    $script:StampDef.Stamps = $stamps
    ConvertTo-Json -InputObject $StampDef -Depth 99 | Out-File $settingsFile -Encoding utf8
}

Function Set-KeyVaultSubscription {
    Param
    (
        [string]
        $cloud = 'AzureCloud',
        [string]
        $Tenantid,
        [string]
        $Subscription
    )

    $KeyVaultCloud = $StampDef.KeyVaultCloud
    if ($null -eq $KeyVaultCloud) {
        $KeyVaultCloud = [PSCustomObject]@{
            "Cloud"        = "AzureCloud"
            "TenantId"     = ""
            "Subscription" = ""
        }
        Add-Member -InputObject $StampDef -MemberType NoteProperty -Name 'KeyVaultCloud' -Value $KeyVaultCloud
    }

    if ($PSBoundParameters.Keys -contains "cloud") { $StampDef.KeyVaultCloud.Cloud = $cloud }
    if ($PSBoundParameters.Keys -contains "Tenantid") { $StampDef.KeyVaultCloud.TenantId = $Tenantid }
    if ($PSBoundParameters.Keys -contains "Subscription") { $StampDef.KeyVaultCloud.Subscription = $Subscription }

    ConvertTo-Json -InputObject $StampDef -Depth 99 | Out-File $settingsFile -Encoding utf8    
}

Function Get-UpdateProgress {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Switch]
        $Brief,
        [Switch]
        $InProgress
    )

    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        [xml]$status = Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackUpdateStatus }
        $ScriptBlock = {
            $duration = ""
            [DateTime]$endTime = Get-Date
            if (![String]::IsNullOrEmpty($_.StartTimeUtc)) {
                if (![String]::IsNullOrEmpty($_.EndTimeUtc)) {
                    $endTime = $_.EndTimeUtc
                }
                $duration = ($endTime - [DateTime]$_.StartTimeUtc).ToString("hh\:mm\:ss")
            }
            if ($_.Status -ne 'Succcess') {
                Write-Output ("{0,-12} {1,-10}  {2,-10}   {3}" -f $_.FullStepIndex, $duration, $_.Status, $_.Description)
            }
        }

        if ($Brief) {
            if ($status) {
                $status.SelectNodes("//Step") | ForEach-Object $ScriptBlock
            }
        }
        elseif ($InProgress) {
            if ($status) {
                $status.SelectNodes("//Step") | Where-Object { $_.Status -notlike "Success" } | ForEach-Object $ScriptBlock
            }
        } 
        else {
            if ($status) {
                $status.SelectNodes("//Step") | Format-Table FullStepIndex, Index, Name, StartTimeUtc, Status, EndTimeUtc -AutoSize
            }
        }
    }
}

Function Get-UpdateVerboseLog {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath

    )

    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackUpdateVerboseLog -FullLog } | Out-File $OutputPath -Force
    }
}

Function Get-UpdateActionStatusXml {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath
    )

    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackUpdateStatus } | Out-File $OutputPath -Force
    }
}

Function Get-StampInformation {
    Param
    (
        [Parameter(Mandatory = $true)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp
    )

    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        $info = Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackStampInformation }
        $info
    }
}

function Test-Unlock {
    Param
    (

        [Parameter(Mandatory = $false)]
        $PepSession
    )   
    $test = Invoke-Command $PepSession { Get-Host } -ErrorAction SilentlyContinue
    return !($null -eq $test)
}

function Unlock-RpSubscription {
    Param
    (
        [Parameter(Mandatory = $false, position = 0)]
        [ArgumentCompleter( { (Get-Stamp).Name | Sort-Object })]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter (Mandatory = $true)]
        [String]
        $ProductId,
        [string]
        $PrincipalId
    )
    Connect-AzureStack -Stamp $Stamp
    $PrincipalId = Get-Principalid
    $pep = Connect-PepSession -Stamp $Stamp
    if ($pep) {
        if (Test-Unlock -PepSession $pep) {
            Invoke-Command $pep { Import-Module Azs.DeploymentProvider.Security -ErrorAction Stop -Verbose }
            Invoke-Command $pep { Unlock-AzsProductSubscription -ProductId $Using:ProductId -PrincipalId $Using:PrincipalId }
        }
        else {
            Write-Host -ForegroundColor Cyan "PEP must be unlocked to perform this function"
        }
    }
}

function Get-Principalid {
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = [Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient]::new($profile)
    $token = $profileClient.AcquireAccessToken($profile.DefaultContext.Tenant.Id)
    $segments = $token.AccessToken.Split('.')
    $s = $segments[1]
    if ($s.Length % 4 -ne 0) { $s = $s + [string]::new('=', 4 - $s.Length % 4) }
    $s = $s.Replace('-', '+')
    $s = $s.Replace('_', '/')
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
    $json = $json.Replace('AppId', 'AppId2')
    $payload = $json | ConvertFrom-Json
    $principalId = $payload.oid
    $principalId
}