# Create HA Infrastructure for an AppServices deployment

This template will deploy all the infrastructure required for Azure Stack AppServices. The template deploys a VNET with the subnets required by AppService. It also creates a 2 node SQL Always On cluster and a 2 node File server cluster using storage spaces direct. To support the clusters a pair of domain controllers are alos provisioned.

