[CmdletBinding()]
Param(
    [String]
    [Parameter(Mandatory = $true)]
    $ResourceGroupName
)


function logheader ($heading, $filepath) {
    Write-Output $('=' * ($heading.length)) | Out-File -FilePath $filepath -Append
    Write-Output $heading | Out-File -FilePath $filepath -Append
    Write-Output $('=' * ($heading.length)) | Out-File -FilePath $filepath -Append
}

 
$resourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ($resourceGroup -eq $null) {
    Write-Host -ForegroundColor Red "Resource Group $ResourceGroupName not found"
    Exit
}
Write-Host -ForegroundColor Green "Resource Group $ResourceGroupName found OK"

$deployments = Get-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName
Write-Host -ForegroundColor Green "Found" $deployments.Count "deployments in resource group $resourceGroupName"

$deployments | ft -Property DeploymentName, ProvisioningState, Mode, Timestamp 
$faileddeployments = $deployments #| where {$_.ProvisioningState -ne 'Succeeded'}
if ($faileddeployments.Count -ge 1) {
    Write-Host -ForegroundColor Green 'Logging failed deployments'
    foreach ($deployment in $faileddeployments) {
        #set up a log file
        $name = $deployment.DeploymentName
        $logfile = "$ResourceGroupName-$name.json"
        Write-Host -ForegroundColor White "Writing deployment log file to $logfile" 
        Remove-Item $logfile -Confirm -ErrorAction SilentlyContinue

        #write a header
        logheader "Deployment details for deployment $name" $logfile

        #Template link if available - not available if deployed via portal
        Write-Host -ForegroundColor Green Getting deployment informaion for deployment $deployment.DeploymentName
        if ($deployment.TemplateLink -ne $null) {
            logheader "Template Link Information" $logfile
            $deployment.TemplateLink | ConvertTo-Json | Out-File -FilePath $logfile -Append
            logheader "Template Content" $logfile
            $template = Invoke-WebRequest -Uri $deployment.TemplateLink.Uri
            $template.Content | Out-File -FilePath $logfile -Append
        } 

        #Deployment parameters
        logheader "Depployment Paramaters" $logfile 
        $deployment.Parameters | ConvertTo-Json | Out-File -FilePath $logfile -Append
        
        #Deployment out puts if any
        if ($deployment.Outputs -ne $null) {
            logheader "Deployment Outputs" $logfile
            $deployment.OutputsString | Out-File -FilePath $logfile -Append
        } 

        #deployment operations
        $operations = Get-AzureRmResourceGroupDeploymentOperation -DeploymentName $deployment.DeploymentName -ResourceGroupName $ResourceGroupName
        Write-Host -ForegroundColor Green "Getting deployment operations for deployment" $deployment.DeploymentName
        logheader "Deployment Operations" $logfile 
        $operations | ConvertTo-Json -Depth 3 | Out-File -FilePath $logfile -Append

        #All resources from deployment
        Write-Host -ForegroundColor Green "Getting Additional information all resources"
        logheader "Resources in deployment" $logfile
        foreach ($resid  in ($operations.Properties.targetResource.id | select  -Unique)) {
            Get-AzureRmResource -ResourceId $resid | convertto-json -Depth 3 | Out-File -FilePath $logfile -Append
        }
    }
}


        #Additional information for VMs and Extensions
        Write-Host -ForegroundColor Green "Getting Additional information for any VM resources"
        $logfile = "$ResourceGroupName-vm-extensions.json"
        Write-Host -ForegroundColor White "Writing deployment log file to $logfile" 
        Remove-Item $logfile -Confirm -ErrorAction SilentlyContinue
        foreach ($vm in (Get-AzureRmVM -ResourceGroupName $ResourceGroupName)) {
            Write-Host -ForegroundColor Green "Getting details for vm" $vm.Name 
            $vmstatus = Get-AzureRmVm  -ResourceGroupName $ResourceGroupName -Name $vm.name -Status

            logheader ("VM status for VM" + $vmstatus.Name) $logfile
            $vmstatus.StatusesText| Out-File -FilePath $logfile -Append

            Write-Host -ForegroundColor Green "Getting VM Agent Status for VM" $vmstatus.Name
            logheader ("VM Agent status for VM" + $vmstatus.Name) $logfile
            $vmstatus.VMAgentText | Out-File -FilePath $logfile -Append

            Write-Host -ForegroundColor Green "Getting Installed Agent Extensions for VM" $vmstatus.Name
            logheader ("Installed Extensions for VM" + $vmstatus.Name) $logfile
            $vmstatus.ExtensionsText | Out-File -FilePath $logfile -Append
        }

        #Additional information for VM ScaleSets
        Write-Host -ForegroundColor Green "Getting Additional information for any VM Scaleset resources"
        $logfile = "$ResourceGroupName-scaleset-extensions.json"
        Write-Host -ForegroundColor White "Writing deployment log file to $logfile" 
        Write-Host -ForegroundColor Green "Getting Additional information for any VM ScaleSet resources"
        foreach ($scaleset in (Get-AzureRmVmss -ResourceGroupName $ResourceGroupName)) {

            $vmss = Get-AzureRmVmssvm  -ResourceGroupName $ResourceGroupName -Name $scaleset.Name
            foreach ($vm in $vmss) {
                $vmssi = Get-AzureRmVmssVM -InstanceView -ResourceGroupName $ResourceGroupName  -VMScaleSetName $vmop.Properties.TargetResource.ResourceName -InstanceId $vm.InstanceID
                
                Write-Host -ForegroundColor Green "Getting VM Status for ScaleSet Instance" $vm.Name
                logheader ("VM status for ScaleSet Instance" + $vm.Name) $logfile
                $vmssi.Statuses | ConvertTo-Json -Depth 5| Out-File -FilePath $logfile -Append

                Write-Host -ForegroundColor Green "Getting VM Agent Status for ScaleSet Instance" $vm.Name
                logheader ("VM Agent status for VM" + $vmssi.Name) $logfile
                $vmssi.VMAgent | ConvertTo-Json -Depth 5| Out-File -FilePath $logfile -Append

                Write-Host -ForegroundColor Green "Getting Installed Agent Extensions for ScaleSet Instance" $vm.Name
                logheader ("Installed Extensions for VM" + $vmssi.Name) $logfile
                $vmssi.Extensions | ConvertTo-Json -Depth 5| Out-File -FilePath $logfile -Append
            }
        }
