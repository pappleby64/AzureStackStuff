$location = 'mas1'
$resourceGroupName = 'Networking05'
$externalGatewayIP = '10.18.10.2'
$externalPrefix = '10.100.0.0/16'
$sharedSecret = "password"

#Create a resource Group
Write-Host -ForegroundColor Green 'Creating Resource Group'
$rg = New-AzureRmResourceGroup -Location $location -Name $resourceGroupName

#Routetable that will be associated with subnet1
Write-Host -ForegroundColor Green 'Creating Route Table'
$routeTable = New-AzureRmRouteTable -Name 'RouteTable' -ResourceGroupName $resourceGroupName -Location $location 

#Create subnets vms on subnet1 will use NVA vms on subnet 2 will use AzureStack Gateway
Write-Host -ForegroundColor Green 'Creating Subnets and Vnet'
$subnet1 = New-AzureRmVirtualNetworkSubnetConfig -Name 'Subnet-1' -AddressPrefix 10.1.0.0/24 -RouteTable $routeTable
$subnet2 = New-AzureRmVirtualNetworkSubnetConfig -Name 'Subnet-2' -AddressPrefix 10.1.1.0/24

#create subnet for NVA and Gateway
$nvaSubnet = New-AzureRmVirtualNetworkSubnetConfig -Name 'Subnet-nva' -AddressPrefix 10.1.253.0/27
$gatewaySubnet = New-AzureRmVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -AddressPrefix 10.1.254.0/27

#create the Vnet
$vnet = New-AzureRmVirtualNetwork -Name AzureStackVnet -ResourceGroupName $resourceGroupName -Location $location -AddressPrefix 10.1.0.0/16 -Subnet $subnet1, $subnet2, $nvaSubnet, $gatewaySubnet

#create local gateway, vnet gateway and connection
Write-Host -ForegroundColor Green 'Creating local gateway, VnetGateway and connection'
$gatewaySubnet = $vnet.Subnets | Where-Object {$_.Name -eq 'GatewaySubnet'}
$localGateway = New-AzureRmLocalNetworkGateway -Name 'LocalGateway' -ResourceGroupName $resourceGroupName -Location $location -GatewayIpAddress $externalGatewayIP -AddressPrefix $externalPrefix 
$publicIP = New-AzureRmPublicIpAddress -Name 'GatewayIP' -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Dynamic
$gwIpconfig = New-AzureRMVirtualNetworkGatewayIpConfig -Name 'GwIpConfig' -SubnetId $gatewaySubnet.Id -PublicIpAddressId $publicIP.Id
$vnetGateway = New-AzureRmVirtualNetworkGateway -Name 'VnetGateway' -ResourceGroupName $resourceGroupName -Location $location -GatewayType Vpn -VpnType RouteBased -IpConfigurations $gwIpconfig

#Make the connection
$connection = New-AzureRmVirtualNetworkGatewayConnection -Name 'Connection1'-ResourceGroupName $resourceGroupName -Location $location -VirtualNetworkGateway1 $vnetGateway -LocalNetworkGateway2 $localGateway -ConnectionType IPsec -SharedKey $sharedSecret 

#Create a storage account & local VM credential
Write-Host -ForegroundColor Green 'Creating Storage Account'
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'localadmin', (ConvertTo-SecureString -String 'p@ssw0rd1' -AsPlainText -Force)
$storageAccount = New-AzureRmStorageAccount -ResourceGroupName $resourceGroupName -Location $location -Name 'networkingvmstorage4' -Type Standard_LRS

#Create TESTVM1
Write-Host -ForegroundColor Green 'Creating VM1'
$netInterface = New-AzureRmNetworkInterface -Name 'nic1' -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId ($vnet.Subnets | Where-Object {$_.Name -eq 'Subnet-1'}).Id
$VirtualMachine = New-AzureRmVMConfig -VMName 'TestVM1' -VMSize Standard_D2
$VirtualMachine = Set-AzureRmVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName 'TestVM1' -Credential $Credential 
$VirtualMachine = Set-AzureRmVMSourceImage -VM $VirtualMachine -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2016-Datacenter -Version "latest"
$VirtualMachine = Add-AzureRmVMNetworkInterface -VM $VirtualMachine -Id $netInterface.Id
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "testvm1/vhds/" + $OSDiskName + ".vhd"
$VirtualMachine = Set-AzureRmVMOSDisk -VM $VirtualMachine -Name 'osdisk' -VhdUri $OSDiskUri -CreateOption FromImage
New-AzureRmVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VirtualMachine

#Create TESTVM2
Write-Host -ForegroundColor Green 'Creating VM2'
$netInterface = New-AzureRmNetworkInterface -Name 'nic2' -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId ($vnet.Subnets | Where-Object {$_.Name -eq 'Subnet-2'}).Id
$VirtualMachine = New-AzureRmVMConfig -VMName 'TestVM2' -VMSize Standard_D2
$VirtualMachine = Set-AzureRmVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName 'TestVM2' -Credential $Credential 
$VirtualMachine = Set-AzureRmVMSourceImage -VM $VirtualMachine -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2016-Datacenter -Version "latest"
$VirtualMachine = Add-AzureRmVMNetworkInterface -VM $VirtualMachine -Id $netInterface.Id
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "testvm2/vhds/" + $OSDiskName + ".vhd"
$VirtualMachine = Set-AzureRmVMOSDisk -VM $VirtualMachine -Name 'osdisk' -VhdUri $OSDiskUri -CreateOption FromImage
New-AzureRmVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VirtualMachine

#Create NVA
Write-Host -ForegroundColor Green 'Creating Windows NVA'
$pIp = New-AzureRmPublicIpAddress -Name 'NVAPublicIP' -ResourceGroupName $ResourceGroupName -Location $Location -AllocationMethod Dynamic
$netInterface = New-AzureRmNetworkInterface -Name 'nicnva' -ResourceGroupName $ResourceGroupName -Location $Location -SubnetId ($vnet.Subnets | Where-Object {$_.Name -eq 'Subnet-nva'}).Id -PublicIpAddressId $pIp.Id
$VirtualMachine = New-AzureRmVMConfig -VMName 'WindowsNVA' -VMSize Standard_D2
$VirtualMachine = Set-AzureRmVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName 'WinNVA' -Credential $Credential
$VirtualMachine = Set-AzureRmVMSourceImage -VM $VirtualMachine -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2016-Datacenter -Version "latest"
$VirtualMachine = Add-AzureRmVMNetworkInterface -VM $VirtualMachine -Id $netInterface.Id
$OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "winnva/vhds/" + $OSDiskName + ".vhd"
$VirtualMachine = Set-AzureRmVMOSDisk -VM $VirtualMachine -Name 'osdisk' -VhdUri $OSDiskUri -CreateOption FromImage
New-AzureRmVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $VirtualMachine

Write-Host -ForegroundColor Green 'Adding custome route'
Add-AzureRmRouteConfig -Name "WinNVARoute" -AddressPrefix $externalPrefix -NextHopType VirtualAppliance -NextHopIpAddress $netInterface.IpConfigurations[0].PrivateIpAddress -RouteTable $routeTable
Set-AzureRmRouteTable -RouteTable $routeTable 

