$global:AzGlobals = @{
    ResourceGroup = "azlabs-rg"
    Location = "eastus"
    Domain = "io5m1fhuzqlefl4pehndptjbxg.bx.internal.cloudapp.net"
    LogWorkspace = "log-ws"
    KeyVault = "azlabs-kvt"
    KeyVaultResGroup = "azlabs-core-rg"
    SecurityGroup = "subnet-nsg"
    VMSize = "Standard_B1S"
    VNet = "azlabs-vnet"
    VNetSubnet = "192.168.0.0/24"
    WindowsSubnet = "192.168.0.0/28"
    LinuxSubnet = "192.168.0.16/28"
}

$AzGlobals.Add("SentinelSolution", "SecurityInsights($($AzGlobals.LogWorkspace))")