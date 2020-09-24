# Variables for common values used throughout the script.
$location = 'east'
$ResourceGroupNmae = 'PsVnetPeering'
$VMLocalAdminUser = "LocalAdmin"
$Credential = Get-Credential -UserName $VMLocalAdminUser -Message "Account for new VM"
$VMSize = "Standard_DS1"

# Create a resource group.
New-AzResourceGroup -Name $ResourceGroupNmae  -Location $location

# Create virtual network 1.
$subnet1 = New-AzVirtualNetworkSubnetConfig -Name 'Subnet1' -AddressPrefix '10.100.0.0/24'
$vnet1 = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupNmae -Name 'myVnet1' -AddressPrefix '10.100.0.0/16' -Location $location -Subnet $subnet1

# Create virtual network 2.
$subnet2 = New-AzVirtualNetworkSubnetConfig -Name 'Subnet1' -AddressPrefix '10.200.0.0/24'
$vnet2 = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupNmae -Name 'myVnet2' -AddressPrefix '10.200.0.0/16' -Location $location -Subnet $subnet2

# Peer VNet1 to VNet2.
Add-AzVirtualNetworkPeering -Name 'myVnet1ToMyVnet2' -VirtualNetwork $vnet1 -RemoteVirtualNetworkId $vnet2.Id

# Peer VNet2 to VNet1.
Add-AzVirtualNetworkPeering -Name 'myVnet2ToMyVnet1' -VirtualNetwork $vnet2 -RemoteVirtualNetworkId $vnet1.Id

# Create Public IP and Nics
$pip1 = New-AzPublicIpAddress -Name 'MyPip1'  -ResourceGroupName $ResourceGroupNmae -Location $location -AllocationMethod Dynamic
$nic1 = New-AzNetworkInterface -Name 'MyNic1' -ResourceGroupName $ResourceGroupNmae -Location $location -SubnetId $vnet1.Subnets[0].Id -PublicIpAddressId $pip1.Id

$pip2 = New-AzPublicIpAddress -Name 'MyPip2'  -ResourceGroupName $ResourceGroupNmae -Location $location -AllocationMethod Dynamic
$nic2 = New-AzNetworkInterface -Name 'MyNic2' -ResourceGroupName $ResourceGroupNmae -Location $location -SubnetId $vnet2.Subnets[0].Id -PublicIpAddressId $pip2.Id

#Create VM's
$VirtualMachine1 = New-AzVMConfig -VMName 'MyVM1' -VMSize $VMSize
$VirtualMachine1 = Set-AzVMOperatingSystem -VM $VirtualMachine1 -Windows -ComputerName 'MyVM1' -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate
$VirtualMachine1 = Add-AzVMNetworkInterface -VM $VirtualMachine1 -Id $nic1.Id
$VirtualMachine1 = Set-AzVMSourceImage -VM $VirtualMachine1 -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2016-Datacenter' -Version latest

$VirtualMachine2 = New-AzVMConfig -VMName 'MyVM2' -VMSize $VMSize
$VirtualMachine2 = Set-AzVMOperatingSystem -VM $VirtualMachine2 -Windows -ComputerName 'MyVM2' -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate
$VirtualMachine2 = Add-AzVMNetworkInterface -VM $VirtualMachine2 -Id $nic2.Id
$VirtualMachine2 = Set-AzVMSourceImage -VM $VirtualMachine2 -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2016-Datacenter' -Version latest

New-AzVM -ResourceGroupName $ResourceGroupNmae -Location $location -VM $VirtualMachine1 -Verbose
New-AzVM -ResourceGroupName $ResourceGroupNmae -Location $location -VM $VirtualMachine2 -Verbose
