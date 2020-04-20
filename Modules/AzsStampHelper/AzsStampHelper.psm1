#Requires -Modules @{ ModuleName="AzureRM.Profile"; ModuleVersion="5.5.2" }
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
        throw "Unkown Stamp, Use Get-Stamps to list available stamps"
    }
}

Function GetEnvironment {
    Param
    (
        [Parameter (Mandatory = $true)]
        $Stamp,
        [Parameter (Mandatory = $true)]
        [ValidateSet("Admin", "Tenant")] 
        $EndPoint 
    )

    if ($Tenant) {
        $envName = '{0}-Tenant' -f $Stamp.Name
        $url = 'https://management.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
    }
    else {
        $envName = '{0}-Admin' -f $Stamp.Name
        $url = 'https://adminmanagement.{0}.{1}' -f $stamp.Region, $stamp.ExternalFqdnDomain
    }

    $azEnv = Get-AzureRmEnvironment -Name $envName
    if (!$azEnv) {
        $azEnv = Add-AzureRmEnvironment -Name $envName -ArmEndpoint $url -ErrorAction SilentlyContinue
    }

    if (!$azEnv) {
        throw "Unable to add ARM endpoint $url"
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

    $oldContext = Get-AzureRmContext
    $kvContext = Connect-Azure  -ErrorAction SilentlyContinue
    if (!$kvContext) {
        Write-Host -ForegroundColor Cyan "Login to Azure is required to access Credentials in Key Vault"
        return
    }
    $kvsecret = Get-AzureKeyVaultSecret -VaultName $valultName -Name $secretName -ErrorAction SilentlyContinue
    if ($oldContext) {
        $oldContext | Select-AzureRmContext | Out-Null
    }
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
        Write-Host -ForegroundColor Cyan "Accessing keyvault to retrieve credentials, Enter Azure Credentials if prompted"
        $cred = GetUserCredential -user $User
        if ($cred) { $accountParams.Add('Credential', (GetUserCredential $User)) }
    }

    if (![String]::IsNullOrEmpty($User.TenantId)) {
        $accountParams.Add('Tenant', $User.TenantId)
    }

    if (![String]::IsNullOrEmpty($User.Subscription)) {
        $accountParams.Add('Subscription', $User.Subscription)
    }
    Write-Host -ForegroundColor Cyan "Connecting to Azure Stack $($Environment.Name), Enter Credentials if prompted"
    $result = Add-AzureRmAccount @accountParams
    $result.Context 
}

Function Prompt {
    Write-Host -ForegroundColor Cyan -NoNewline "[$((Get-AzureRmContext).Environment.Name)]"
    Write-Host -NoNewline "$(Get-Location)"
    return "> "
}

Export-ModuleMember -Function Prompt

Function Connect-Azure {
    $cloud = $StampDef.AzureCloud.Cloud
    if ([string]::IsNullOrEmpty($cloud)) { $cloud = 'AzureCloud' }
    $tenant = $StampDef.AzureCloud.TenantId
    $sub = $StampDef.AzureCloud.Subscription
    $ctx = Get-AzureRmContext -ListAvailable  -ErrorAction SilentlyContinue | Where-Object { ($_.Environment).Name -eq $cloud }
    if (-not [string]::IsNullOrEmpty($tenant)) { $ctx = Get-AzureRmContext -ListAvailable  -ErrorAction SilentlyContinue | Where-Object { ($_.Tenant).Id -eq $tenant } }
    if (-not [string]::IsNullOrEmpty($sub)) { $ctx = Get-AzureRmContext -ListAvailable  -ErrorAction SilentlyContinue | Where-Object { ($_.Subscription).Name -eq $sub } }
    $ctx = $ctx | Select-Object -First 1

    if ($ctx) {
        $ctx | Select-AzureRmContext | Out-Null
    }
    else {
        $AccountParams = @{ }
        if (-not [string]::IsNullOrEmpty($cloud)) { $AccountParams.Add("EnvironmentName", $cloud) }
        if (-not [string]::IsNullOrEmpty($tenant)) { $AccountParams.Add("Tenant", $tenant) }
        if (-not [string]::IsNullOrEmpty($sub)) { $AccountParams.Add("Subscription", $sub) }
        $account = Add-AzureRmAccount @AccountParams
        $ctx = $account.Context
    }
    $ctx
}

Export-ModuleMember -Function Connect-Azure

Function Connect-AzureStack {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Switch]
        $Tenant
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }

    if ($Tenant) {
        $azEnv = GetEnvironment -Stamp $stampInfo -EndPoint Tenant
        $user = $stampInfo.TenantUser
    }
    else {
        $azEnv = GetEnvironment -Stamp $stampInfo -EndPoint Admin
        $user = $stampInfo.AdminUser
    }

    Write-Host -ForegroundColor Cyan "Connecting to AzureStack stamp $Stamp ...."
    $ctx = Get-AzureRmContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -eq $azEnv.Name }
    if ($ctx) {
        Write-Host -ForegroundColor Cyan "Using existing AzureRmContext for user $($ctx.Account.Id)"
        $ctx | Select-AzureRmContext | Out-Null
    }
    else {
        $ctx = ConnectAzureStackUser -User $user -Environment $azEnv
    }
    if ($ctx.Environment.Name -eq $azEnv.Name -and $ctx.Account.Id -eq $user.UserName) {
        Write-Host -ForegroundColor Cyan "Succesfully connected to $($azEnv.Name) as $($user.UserName)"
    }
}

Export-ModuleMember -Function Connect-AzureStack

Function Connect-AzureStackPortal {
    Param
    (
        [Parameter(Mandatory = $true)]
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

    if (![String]::IsNullOrEmpty($User.VaultName) -and ![String]::IsNullOrEmpty($User.SecretName)) {
        (GetKeyVaultSecret -valultName $user.VaultName -secretName $user.SecretName ).SecretValueText | clip.exe
        Write-Host -ForegroundColor Cyan "Login using account $($user.UserName) The password is on the clipboard"
        Write-Host -ForegroundColor Cyan "Press enter to launch $Browser"
        Read-Host
    }
    Start-Process -FilePath  $url
}

Export-ModuleMember -Function Connect-AzureStackPortal

Function Get-PepSession {
    Param
    (
        [Parameter(Mandatory = $true, position = 0)]
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
        $ErcsVM       
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    $pepUser = $stampInfo.CloudAdminUser
 
    
    if ($PSCmdlet.ParameterSetName -ne 'SessionName') {
        if (![String]::IsNullOrEmpty($ErcsVM)) {
            switch ($ErcsVM) {
                'ERCS01' { $vms = $stampInfo.ErcsVMs[0] }
                'ERCS02' { $vms = $stampInfo.ErcsVMs[1] }
                'ERCS03' { $vms = $stampInfo.ErcsVMs[2] }
            }
        }
        else {
            $vms = $stampInfo.ErcsVMs
        }      

        $session = Get-PSSession | Where-Object { $_.ComputerName -in $vms -and $_.State -eq 'Opened' } | Sort-Object Id -Descending | Select-Object -First 1

                        
        if (!$session) {
            Write-Host -ForegroundColor Cyan "Accessing keyvault to retrieve pep credentials, Enter Azure Credentials if prompted"
            $pepPassword = (GetKeyVaultSecret -valultName $pepUser.VaultName -secretName $pepUser.SecretName).SecretValue
            if ($pepPassword) {
                $pepCred = New-Object System.Management.Automation.PSCredential $pepUser.UserName, $pepPassword
            }
            else {
                Write-Host -ForegroundColor Cyan "Enter PEP credential"
                $pepCred = Get-Credential -Message "Enter PEP credentials" -UserName $pepUser.userName
            }
            $sessionName = "{0}{1}" -f $Stamp, (Get-Date).ToString('HHmm')
            $usCulture = New-PSSessionOption -Culture en-US -UICulture en-US
            foreach ($pepip in $vms) { 
                Write-Host -ForegroundColor Cyan "Creating PEP session on $Stamp using IP $pepip"
                $session = New-PSSession -ComputerName $pepip -ConfigurationName PrivilegedEndPoint -Credential $pepCred -Name $sessionName -SessionOption $usCulture -ErrorAction SilentlyContinue
                if ($session) {
                    break
                }
            }
        }
        if (!$session) {
            Write-Host -ForegroundColor Red "Failed to create PEP session"
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

Export-ModuleMember -Function Get-PepSession

Function Enter-PepSession {
    Param
    (
        [Parameter(Mandatory = $true, position = 0)]
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
        $ErcsVM       
    )
    $session = Get-PepSession @PSBoundParameters
    Enter-PSSession -Session $session
}

Export-ModuleMember -Function Enter-PepSession

Function Unlock-PepSession {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp
    )

    $pep = Get-PepSession -Stamp $Stamp
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

Export-ModuleMember -Function Unlock-PepSession

Function Close-PepSession {
    Param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
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

Export-ModuleMember -Function Close-PepSession

Function Save-PepSession {
    Param
    (
        [Parameter(Mandatory = $true)]
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

Export-ModuleMember -Function Save-PepSession

Function Clear-StampCache {
    foreach ($stamp in $StampDef.Stamps) {
        $ctx = Get-AzureRmContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -like "$($Stamp.Name)-*" }
        $ctx | Remove-AzureRmContext -Force
        $env = Get-AzureRmEnvironment | Where-Object { $_.Name -like "$($Stamp.Name)-*" }
        $env | Remove-AzureRmEnvironment | Out-Null
    }
}

Export-ModuleMember -Function Clear-StampCache

Function Get-Stamps {
    $StampDef.Stamps
}

Export-ModuleMember -Function Get-Stamps

Function Add-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        [Parameter(Mandatory = $true,ParameterSetName = "region")]
        [string]
        $Region,
        [Parameter(Mandatory = $true,ParameterSetName = "region")]
        [string]
        $Fqdn,
        [Parameter(Mandatory = $true,ParameterSetName = "regionfqdn")]
        [string]
        $ReqionFqdn,
        [Parameter(Mandatory)]
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
        $region = $split[0]
        $fqdn = $split[1..-1] -join '.'
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

Export-ModuleMember -Function Add-Stamp

Function Set-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
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

Export-ModuleMember -Function Set-Stamp

Function Remove-Stamp {
    Param
    (
        [Parameter(Mandatory = $true)]
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

Export-ModuleMember -Function Remove-Stamp

Function Set-AzureSubscription {
    Param
    (
        [string]
        $cloud = 'AzureCloud',
        [string]
        $Tenantid,
        [string]
        $Subscription
    )

    $AzureCloud = $StampDef.AzureCloud
    if ($null -eq $AzureCloud) {
        $AzureCloud = [PSCustomObject]@{
            "Cloud"        = "AzureCloud"
            "TenantId"     = ""
            "Subscription" = ""
        }
        Add-Member -InputObject $StampDef -MemberType NoteProperty -Name 'AzureCloud' -Value $AzureCloud
    }

    if ($PSBoundParameters.Keys -contains "cloud") { $StampDef.AzureCloud.Cloud = $cloud }
    if ($PSBoundParameters.Keys -contains "Tenantid") { $StampDef.AzureCloud.TenantId = $Tenantid }
    if ($PSBoundParameters.Keys -contains "Subscription") { $StampDef.AzureCloud.Subscription = $Subscription }

    ConvertTo-Json -InputObject $StampDef -Depth 99 | Out-File $settingsFile -Encoding utf8    
}

Export-ModuleMember -Function Set-AzureSubscription

Function Get-UpdateProgress {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Switch]
        $Brief,
        [Switch]
        $InProgress
    )

    $pep = Get-PepSession -Stamp $Stamp

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
            Write-Output ("{0,-8} {1,-10}  {2,-10}   {3}" -f $_.FullStepIndex, $duration, $_.Status, $_.Description)
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

Export-ModuleMember -Function Get-UpdateProgress

Function Get-UpdateVerboseLog {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath

    )

    $pep = Get-PepSession -Stamp $Stamp
    Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackUpdateVerboseLog -FullLog } | Out-File $OutputPath -Force
}

Export-ModuleMember -Function Get-UpdateVerboseLog

Function Get-UpdateActionStatusXml {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $true)]
        [string]
        $OutputPath

    )

    $pep = Get-PepSession -Stamp $Stamp
    Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackUpdateStatus } | Out-File $OutputPath -Force
}

Export-ModuleMember -Function Get-UpdateActionStatusXml

Function Get-StampInformation {
    Param
    (
        [Parameter(Mandatory = $true)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp
    )

    $pep = Get-PepSession -Stamp $Stamp
    $info = Invoke-Command -Session $pep -ScriptBlock { Get-AzureStackStampInformation }
    $info
}

Export-ModuleMember -Function Get-StampInformation

Function Get-WinRmTrustedHost {
    $currentTrustedHostsValue = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    Write-Host -ForegroundColor Cyan "Existing WinRM TrustedHosts values:"
    Write-Host $currentTrustedHostsValue
}

Export-ModuleMember -Function Get-WinRmTrustedHost

Function Set-WinRmTrustedHost {
    Param
    (
        [Parameter(Mandatory = $false, position = 0)]
        [Validatescript( { ValidateStampName -Stamp $_ })]
        [string]
        $Stamp,
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    [Security.Principal.WindowsPrincipal]$id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host -ForegroundColor Cyan 'using Set-WinRmTrustedHost requires running PowerShell in Admin mode'
        return
    }

    if ($Stamp) {
        $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
        Write-Host -ForegroundColor Cyan "Getting ERCS VM IP addresses for stamp $Stamp"
        $trustedHostIPs = $stampInfo.ErcsVMs
    }
    else {
        Write-Host -ForegroundColor Cyan "Getting ERCS VM IP addresses for all lab stamps"
        $trustedHostIPs = $StampDef.Stamps.ErcsVMs
    }

    $currentTrustedHostsValue = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value

    if (!$Force -and -not [string]::IsNullOrEmpty($currentTrustedHostsValue)) {
        Write-Host -ForegroundColor Cyan "Existing WinRM TrustedHosts value:"
        Write-Host $currentTrustedHostsValue
        $existingHosts = $currentTrustedHostsValue.split(',')
        if ('*' -in $existingHosts) {
            Write-Host -ForegroundColor Cyan "Leaving existing wildcard"
            return 
        }
        $trustedHostIPs += $existingHosts
    }
    $trustedHosts = ($trustedHostIPs | Sort-Object -Unique) -join ","

    Write-Host -ForegroundColor Cyan "Setting WinRM TrustedHosts to:"
    Write-Host $trustedHosts

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $trustedHosts -Confirm:$false -Force
}

Export-ModuleMember -Function Set-WinRmTrustedHost
