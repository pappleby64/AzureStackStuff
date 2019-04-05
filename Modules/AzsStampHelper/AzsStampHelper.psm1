#Requires -Modules @{ ModuleName="AzureRM.Profile"; ModuleVersion="5.5.2" }
$settingsFolder = "$env:LOCALAPPDATA\AzsStampHelper"
$settingsFile = "$settingsFolder\StampDef.json"

if (!(Test-Path $settingsFolder)) {
    New-Item -ItemType Directory $settingsFolder | Out-Null
}


if (Test-Path $settingsFile) {
    $StampDef = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
}

Function Prompt {
    Write-Host -ForegroundColor Cyan -NoNewline "[$((Get-AzureRmContext).Environment.Name)]"
    Write-Host -NoNewline "$(Get-Location)"
    return "> "
}

Export-ModuleMember -Function Prompt

Function Get-Environment {
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
        $azEnv = Add-AzureRmEnvironment -Name $envName -ArmEndpoint $url 
    }
    $azEnv
}

Function Get-KeyVaultSecret {
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
    $kvContext = Get-AzureRmContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -eq 'AzureCloud' }
    if (!$kvContext) {
        Write-Host -ForegroundColor Cyan "No Azure context to access keyvault found, press anykey to login to Azure"
        Read-Host
        $kvaccount = Add-AzureRmAccount  -ErrorAction SilentlyContinue
        if (!$kvaccount) {
            Write-Host -ForegroundColor Cyan "Login to Azure required !"
            return
        }
        $kvContext = $kvaccount.Context
    }
    else {
        Write-Host -ForegroundColor Cyan "Using existing AzureCloud context to access keyvault"
    }
    $kvContext | Select-AzureRmContext | Out-Null
    $kvsecret = Get-AzureKeyVaultSecret -VaultName $valultName -Name $secretName -ErrorAction SilentlyContinue
    if ($oldContext) {
        $oldContext | Select-AzureRmContext | Out-Null
    }
    $kvsecret
}

Function Connect-Azure {
    $ctx = Get-AzureRmContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -eq 'AzureCloud' }
    if ($ctx) {
        $ctx | Select-AzureRmContext | Out-Null
    }
    else {
        Add-AzureRmAccount | Out-Null
    }
    Get-AzureRmContext
}

Export-ModuleMember -Function Connect-Azure

Function Connect-AzureStack {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Stamp,
        [Switch]
        $Tenant
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }

    if ($Tenant) {
        $azEnv = Get-Environment -Stamp $stampInfo -EndPoint Tenant
        $userName = $stampInfo.TenantUser
        $secretInfo = $stampInfo.TenantSecret
    }
    else {
        $azEnv = Get-Environment -Stamp $stampInfo -EndPoint Admin
        $userName = $stampInfo.AdminUser
        $secretInfo = $stampInfo.AdminSecret
    }

    Write-Host -ForegroundColor Cyan "Connecting to AzureStack stamp $Stamp ...."
    $ctx = Get-AzureRmContext -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Environment.Name -eq $azEnv.Name }
    if ($ctx) {
        Write-Host -ForegroundColor Cyan "Using existing AzureRmContext for user $($ctx.Account.Id)"
        $ctx | Select-AzureRmContext | Out-Null
    }
    else {
        if ($null -ne $secretInfo -and $null -ne $userName) {
            Write-Host -ForegroundColor Cyan "Retrieving password for $userName from Azure KeyVault"
            $password = (Get-KeyVaultSecret -valultName $secretInfo.VaultName -SecretName $secretInfo.SecretName ).SecretValue
            $adminCred = New-Object System.Management.Automation.PSCredential $userName, $Password
            Write-Host -ForegroundColor Cyan "Adding AzureRmAccount for $userName"
            Add-AzureRmAccount -Environment $azEnv -Credential $adminCred -Tenant $stampInfo.TenantId | Out-Null 
        }
        else {
            Write-Host -ForegroundColor Cyan "No stored login details available, login interactively"  
            Add-AzureRmAccount -Environment $azEnv -Tenant $stampInfo.TenantId | Out-Null 
        }
        if ((Get-AzureRmContext).Environment.Name -ne $azEnv.Name) {
            Write-Host -ForegroundColor Red "Failed to create a login context for stamp $Stamp"
        }
    }
}

Export-ModuleMember -Function Connect-AzureStack

Function Connect-AzureStackPortal {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Stamp,
        [ValidateSet(
            'InternetExplorer',
            'Chrome'
        )]
        [String]
        $Browser = 'InternetExplorer',
        [Switch]
        $Tenant

    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }


    if ($Tenant) {
        $url = 'https://portal.{0}.{1}/{2}' -f $stampInfo.Region, $stampInfo.ExternalFqdnDomain, $stampInfo.TenantId
        $userName = $stampInfo.TenantUser
        $secretInfo = $stampInfo.TenantSecret
    }
    else {
        $url = 'https://adminportal.{0}.{1}/{2}' -f $stampInfo.Region, $stampInfo.ExternalFqdnDomain, $stampInfo.TenantId
        $userName = $stampInfo.AdminUser
        $secretInfo = $stampInfo.AdminSecret
    }
    $processPath = ''
    switch ($Browser) {
        'InternetExplorer' { $processPath = 'C:\Program Files\Internet Explorer\Iexplore.exe' }
        'Chrome' { $processPath = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe' }
    }
    if (-NOT(Test-Path -Path $processPath)) {
        Write-Host -ForegroundColor Yellow "Selected browser path does not exist: $processPath"
        return
    }

    if ($null -ne $secretInfo -and $null -ne $userName) {
        (Get-KeyVaultSecret -valultName $secretInfo.VaultName -secretName $secretInfo.SecretName ).SecretValueText | clip.exe
        Write-Host -ForegroundColor Cyan "Login using account $userName The password is on the clipboard"
        Write-Host -ForegroundColor Cyan "Press any key to launch $Browser"
    }
    Start-Process -FilePath $processPath -ArgumentList $url
}

Export-ModuleMember -Function Connect-AzureStackPortal

Function Get-PepSession {
    Param
    (
        [Parameter(Mandatory = $true, position = 0)]
        [string]
        $Stamp,
        [Parameter(Mandatory = $false, ParameterSetName = 'SessionName')]
        [string]
        $SessionName
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }
    if ($PSCmdlet.ParameterSetName -ne 'SessionName') {
        $session = Get-PSSession | Where-Object { $_.ComputerName -in $stampInfo.ErcsVMs -and $_.State -eq 'Opened' } | Sort-Object Id -Descending | Select-Object -First 1
        if ($session.State -ne [System.Management.Automation.Runspaces.RunspaceState]::Opened) {
            $session | Remove-PSSession -ErrorAction SilentlyContinue | Out-Null
            $session = $null
        }

        if (!$session) {
            $cloudAdminUser = $stampInfo.CloudAdminUser
            if ([String]::IsNullOrEmpty($cloudAdminUser)) {
                $pepUser = '{0}\Cloudadmin' -f $stampInfo.InternalDomain
            }
            else {
                $pepUser = '{0}\{1}' -f $stampInfo.InternalDomain, $cloudAdminUser
            }
            Write-Host -ForegroundColor Cyan "Retrieving password for $pepUser from Azure KeyVault"
            $pepPassword = (Get-KeyVaultSecret -valultName $stampInfo.CloudAdminSecret.VaultName -secretName $stampInfo.CloudAdminSecret.SecretName).SecretValue
            $pepCred = New-Object System.Management.Automation.PSCredential $pepUser, $pepPassword
            $sessionName = "{0}{1}" -f $Stamp, (Get-Date).ToString('hhmm')
            foreach ($pepip in $stampInfo.ErcsVMs) { 
                Write-Host -ForegroundColor Cyan "Creating PEP session on $Stamp using IP $pepip"
                $session = New-PSSession -ComputerName $pepip -ConfigurationName PrivilegedEndPoint -Credential $pepCred -Name $sessionName -ErrorAction SilentlyContinue
                if ($session) {
                    break
                }
            }
            if (!$session) {
                Write-Host -ForegroundColor Red "Failed to create PEP session"
            }
        }  
    }
    else {
        $cloudAdminUser = $stampInfo.CloudAdminUser
        if ([String]::IsNullOrEmpty($cloudAdminUser)) {
            $pepUser = '{0}\Cloudadmin' -f $stampInfo.InternalDomain
        }
        else {
            $pepUser = '{0}\{1}' -f $stampInfo.InternalDomain, $cloudAdminUser
        }
        $pepPassword = (Get-KeyVaultSecret -valultName $stampInfo.CloudAdminSecret.VaultName -secretName $stampInfo.CloudAdminSecret.SecretName).SecretValue
        $pepCred = New-Object System.Management.Automation.PSCredential $pepUser, $pepPassword
        $session = Get-PSSession -ComputerName $stampInfo.ErcsVMs -Credential $pepCred -Name $SessionName
        if ($session) {
            $session | Connect-PSSession | Out-Null
        }
    }

    return $session
}

Export-ModuleMember -Function Get-PepSession

Function Unlock-PepSession {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Stamp
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }
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
        [string]
        $Stamp,
        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [Switch]
        $All
    )
    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
        if (-NOT ($stampInfo)) {
            Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
            return
        }
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
        [string]
        $Stamp
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }
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

Function Get-UpdateProgress {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Stamp
    )
    $stampInfo = $StampDef.Stamps | Where-Object { $_.Name -eq $Stamp }
    if (-NOT ($stampInfo)) {
        Write-Host -ForegroundColor Cyan "Stamp $Stamp not found"
        return
    }
    $pep = Get-PSSession | Where-Object { $_.ComputerName -in $stampInfo.ErcsVMs }
    if (!$pep) {
        $pep = Get-PepSession -Stamp $Stamp
    }
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
    $status.SelectNodes("//Step") | ForEach-Object $ScriptBlock
}

Export-ModuleMember -Function Get-UpdateProgress
