    Param
    (
        [Parameter(Mandatory = $true)]
        $RemoteIPAddress,
        [Parameter(Mandatory = $true)]
        $AddressSpace
    )

    Install-WindowsFeature -Name Routing
    Install-WindowsFeature -Name 'RSAT-RemoteAccess-PowerShell'
    Install-RemoteAccess -VpnType VpnS2S
    $params = @{
        Name                             = 'ToCloud'
        Protocol                         = 'IKEv2'
        Destination                      = $RemoteIPAddress
        AuthenticationMethod             = 'PSKOnly'
        SharedSecret                     = 'password'
        IPv4Subnet                       = '{0}:{1}' -f $AddressSpace,'200'
        AuthenticationTransformConstants = 'GCMAES256'
        CipherTransformConstants         = 'GCMAES256'
        DHGroup                          = 'Group2'
        EncryptionMethod                 = 'AES256' 
        IntegrityCheckMethod             = 'SHA256' 
        PfsGroup                         = 'PFS2048' 
        EnableQoS                        = 'Enabled' 
        NumberOfTries                    = 0  
    }
    Add-VpnS2SInterface @params -Persistent -CustomPolicy