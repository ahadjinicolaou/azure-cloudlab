function Install-AzLabLogAnalyticsWorkspace {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Location = $AzGlobals.Location,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $WorkspaceName = $AzGlobals.LogWorkspace,

        [Parameter()]
        [string[]] $EventLogs = @(
            "Microsoft-Windows-Sysmon/Operational"),
            
        [Parameter()]
        [string[]] $LogFacilities = @(
            "kern",
            "user",
            "daemon",
            "auth",
            "syslog"
            "authpriv")
    )
    
    # create log analytics workspace
    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName `
        -Name $WorkspaceName -ErrorAction "SilentlyContinue"
    if (-not $ws) {
        $ws = New-AzOperationalInsightsWorkspace -Location $Location -Name $WorkspaceName `
            -Sku Standard -ResourceGroupName $ResourceGroupName
        
        # add windows event log data sources
        $idx = 1
        foreach ($EventLog in $EventLogs) {
            New-AzOperationalInsightsWindowsEventDataSource `
                -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName `
                -Name "winlog$idx-src" -EventLogName $EventLog `
                -CollectErrors `
                -CollectWarnings `
                -CollectInformation | Out-Null
            $idx++
        }

        # enable syslog collection for the workspace
        Enable-AzOperationalInsightsLinuxSyslogCollection `
            -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName | Out-Null
    
        # add linux syslog data sources
        $idx = 1
        foreach ($LogFacility in $LogFacilities) {
            New-AzOperationalInsightsLinuxSyslogDataSource `
                -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName `
                -Name "syslog$idx-src" -Facility $LogFacility `
                -CollectEmergency `
                -CollectAlert `
                -CollectCritical `
                -CollectError `
                -CollectWarning `
                -CollectNotice | Out-Null
            $idx++
        }
        
        Write-Information "Log analytics workspace created." -InformationAction Continue
    }
}

function Connect-AzLabVMsToLogAnalytics {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $WorkspaceName = $AzGlobals.LogWorkspace,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $VMNames
    )
    
    process {
        # make sure the resource group and log analytic workspace exist
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction "Stop"
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName `
            -Name $WorkspaceName -ErrorAction "Stop"
        
        # create outbound NSG rule for the Azure Resource Manager service
        $nsg = Get-AzNetworkSecurityGroup -Name $AzGlobals.SecurityGroup `
            -ResourceGroupName $ResourceGroupName -ErrorAction "SilentlyContinue"
        if (-not $nsg.SecurityRules.name.Contains("AllowSecureHTTP")) {
            # add and persist the rule
            Add-AzNetworkSecurityRuleConfig -Name "AllowSecureHTTP" -NetworkSecurityGroup $nsg `
                -Access Allow -Direction Outbound -Priority 1001 -Protocol * `
                -SourceAddressPrefix "VirtualNetwork" -SourcePortRange * `
                -DestinationAddressPrefix * -DestinationPortRange 443 | `
                Set-AzNetworkSecurityGroup | Out-Null
        }
        
        foreach ($VMName in $VMNames) {
            # make sure the vm exists
            $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -ErrorAction "Stop"
            $winvm = $vm.OSProfile.WindowsConfiguration

            # choose the right VM extension for the OS
            if ($winvm) {
                $extname = "MicrosoftMonitoringAgent"
                $thver = "1.0"
            } else {
                $extname = "OMSAgentForLinux"
                $thver = "1.13"
            }

            # install the VM extension
            $exist = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName `
                -Name $extname -ErrorAction "SilentlyContinue"
            if (-not $exist) {
                $wskey = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroupName -Name $ws.Name
                Set-AzVMExtension -Name $extname -VMName $VMName `
                    -Settings @{ "workspaceId" = $ws.CustomerId } `
                    -ProtectedSettings @{ "workspaceKey" = $wskey.PrimarySharedKey } `
                    -ResourceGroupName $ResourceGroupName -Location $rg.Location `
                    -ExtensionType $extname `
                    -Publisher "Microsoft.EnterpriseCloud.Monitoring" `
                    -TypeHandlerVersion $thver -ErrorAction "Stop" | Out-Null
            }
        }
    }
}
