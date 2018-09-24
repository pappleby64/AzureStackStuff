# Create HA Infrastructure for an AppServices deployment

This template will deploy all the infrastructure required for Azure Stack AppServices installtion. The goal of teh template is to simplify the deployment of the AppService Resource Provider and is therefore intended to be deployed into the Default Provider Subscription. It has been configured with 


 It creates the following resources:

* A virtual network with required subnets 
* network security groups for file server, sql server and AD subnets
* Storage accounts for VM disks and cluster cloud witness
* One internal load balancer for SQL VMs with private IP bound to the SQL Always On listener
* Two VM (WS2016Core) configured as Domain Controllers for a new forest with a single domain
* Two VM (WS2016Core) configured as Storage Spaces Direct File share cluster 
* 3 Availability Sets, for AD, FileServer cluster and SQL cluster 

## Notes

This template uses Azure Stack Marketplace images. These need to be available on your Azure Stack instance:

* Windows Server 2016 Datacenter Core  Image (for AD and File Server VMs)
* Choice of SQL Server 2016 SP2 on Windows Server 2016 (Enterprise, Standard or Developer)
* Latest SQL IaaS Extension 1.2.x (currently 1.2.30)
* Latest DSC Extension (2.76.0, or higher)

## Configuration

* Each SQL VMs will have a single data disk 
* Each File Server VM will have 2 data disks

## Parameters

| Parameter Name | Description | Type | Default Value
| --- | --- | --- | ---
| namePrefix | prefix to beused in resource naming | string | aps
| domainVmSize | VM size for AD VMs | string | Standard_DS1_v2
| filServerVmSize | VM size for file server VMs | string | Standard_DS2_v2
| sqlVmSize | VM size for SQL VMs | string | Standard_DS2_v2
| domainName | dns domain name of new domain | string | Appsvc.local
| adminUsername | Username for domain admin account | string | appsvcadmin
| adminPassword | password for domain admin account | secure string |
| fileShareOwnerUserName | Username for the file share owner account | string | FileShareOwner
| fileShareOwnerPassword | password for file share owner account | secure string |
| fileShareUserUserName | Username for the file share user account | string | FileShareUser
| fileShareUserPassword | password for domain admin account | secure string |
| sqlServerServiceAccountUserName | Username for SQL service account | string | svcSQL
| sqlServerServiceAccountPassword | password for SQL service account | secure string |
| sqlLogin | Username for the SQL login | string | sqlsa
| sqlLoginPassword | password for sql login account | secure string |
| sofsName | Name of the Scale-out File Server | string | sofs01
| shareName | Name of the FileShare | string | WebSites
| _artifactsLocation | Blob store where all deployment artifacts are stored | string |  https://raw.githubusercontent.com/Azure/AzureStack-QuickStart-Templates/master/sql-2016-alwayson| 
| _artifactsLocationSasToken | sas token for artifact location if requires | secure string |  
| location | location to be used for the deployment | string |

## Outputs
The template outputs a number of values that are required when running the AppService RP installer
| Parameter Name | Description 
| --- | --- 
| FileSharePath | FQDN of the file server 
| FileShareOwner | Name of File Share Owner Account 
| FileShareUser | Name of File Share User Account 
| SQLserver | Name of SQL account 
| SQLUser | Name of SQL Server 
