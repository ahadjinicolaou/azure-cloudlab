function Install-AzLabRemoteAccessVNet {
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
        [string] $VNetName = $AzGlobals.VNet,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $SecurityGroupName = $AzGlobals.SecurityGroup
    )

    process {
        # create resource group
        $exist = Get-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction "SilentlyContinue"
        if (-not $exist) {
            New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
        }

        # create network security group
        $nsg = Get-AzNetworkSecurityGroup -Name $SecurityGroupName `
            -ResourceGroupName $ResourceGroupName -ErrorAction "SilentlyContinue"
        if (-not $nsg) {
            $nsg = New-AzNetworkSecurityGroup -Name $SecurityGroupName `
                -ResourceGroupName $ResourceGroupName -Location $Location

            # add remote traffic rules
            Add-AzNetworkSecurityRuleConfig -Name "AllowSSH" -NetworkSecurityGroup $nsg `
                -Protocol "Tcp" -Access "Allow" -Direction "Inbound" -Priority 1000 `
                -SourceAddressPrefix * -SourcePortRange * `
                -DestinationAddressPrefix * -DestinationPortRange 22 |
                Set-AzNetworkSecurityGroup | Out-Null
            Add-AzNetworkSecurityRuleConfig -Name "AllowSecureWinRM" -NetworkSecurityGroup $nsg `
                -Protocol "Tcp" -Access "Allow" -Direction "Inbound" -Priority 1001 `
                -SourceAddressPrefix * -SourcePortRange * `
                -DestinationAddressPrefix * -DestinationPortRange 5986 |
                Set-AzNetworkSecurityGroup | Out-Null
        }

        $VNet = New-AzVirtualNetwork `
            -Name $VNetName -ResourceGroupName $ResourceGroupName -Location $Location `
            -AddressPrefix $AzGlobals.VNetSubnet -Subnet $cfg
        Write-Information "Virtual network $VNetName created." -InformationAction "Continue"

        # make sure all subnets exist
        foreach ($SubnetName in @("linux-subnet", "windows-subnet")) {
            # add the subnet
            $exist = $VNet.Subnets | Select-Object Name, Id | Where-Object Name -eq $SubnetName
            if (-not $exist) {
                if ($SubnetName -eq "linux-subnet") {
                    $SubnetAddressPrefix = $AzGlobals.LinuxSubnet
                } else {
                    $SubnetAddressPrefix = $AzGlobals.WindowsSubnet
                }

                # create the vnet and subnet and assign the NSG to the subnet
                Add-AzVirtualNetworkSubnetConfig -Name $SubnetName -VirtualNetwork $VNet `
                    -AddressPrefix $SubnetAddressPrefix -NetworkSecurityGroupId $nsg.Id | Out-Null
                # updates the network with the subnet configuration
                $VNet | Set-AzVirtualNetwork | Out-Null
            }
            
            Write-Information "Virtual subnet $SubnetName created." -InformationAction "Continue"
        }
    }
}

function New-AzLabVM {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Location = $AzGlobals.Location,

        [Parameter(Mandatory)]
        [ValidateSet("Linux", "WindowsServer", "Windows10")]
        [string] $OperatingSystem,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $VMNames,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $VNetName = $AzGlobals.VNet,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $KeyVaultName =$AzGlobals.KeyVault,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $KeyVaultResGroup = $AzGlobals.KeyVaultResGroup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Domain = $AzGlobals.Domain,

        [Parameter()]
        [System.Security.SecureString] $CertPassword,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $VMSize = $AzGlobals.VMSize,

        [Parameter()]
        [System.Management.Automation.PSCredential] $Credential
    )
    
    begin {
        # ask for credentials
        if (-not $Credential) { $Credential = Get-Credential -Message "Enter the VM credentials." }

        # Windows VMs will need a key vault ready
        if ($OperatingSystem.StartsWith("Windows")) {
            $kv = Get-AzKeyVault -ResourceGroupName $KeyVaultResGroup `
                -VaultName $KeyVaultName -ErrorAction "SilentlyContinue"
            if (-not $kv) {
                # create the key vault
                $kv = New-AzKeyVault -ResourceGroupName $KeyVaultResGroup -Location $Location `
                    -VaultName $KeyVaultName -EnabledForDeployment -EnabledForTemplateDeployment `
                    -ErrorAction "Stop"
                Write-Information -Message "Key vault $KeyVaultName created."
            }
        }
    }
    
    process {
        # get the vnet and find the subnet (VMs are segmented by OS)
        $SubnetName = If ($OperatingSystem.StartsWith("Windows")) {"windows-subnet"} Else {"linux-subnet"}
        $VNet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName `
            -ErrorAction "Stop"
        $subs = $VNet.Subnets | Select-Object Name, Id | Where-Object Name -eq $SubnetName

        foreach ($VMName in $VMNames) {
            # skip over existing VMs
            $exist = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction "SilentlyContinue"
            if ($exist) {
                Write-Information -Message "VM $VMName already exists."
                continue
            }

            # create public IP address
            $pip = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName `
                -Location $Location -Name "$VMName-pip" -AllocationMethod "Static" `
                -IdleTimeoutInMinutes 5 -Force

            # create a virtual NIC and assign the public IP and subnet
            $nic = New-AzNetworkInterface -Name "$VMName-nic" -ResourceGroupName $ResourceGroupName `
                -Location $Location -SubnetId $subs.Id -PublicIpAddressId $pip.Id -Force

            # initialize the VM config
            $vm = New-AzVMConfig -VMName $VMName -VMSize $VMSize | Add-AzVMNetworkInterface -Id $nic.Id
            if ($OperatingSystem -eq "Linux") {
                $vm | Set-AzVMOperatingSystem -Linux -ComputerName $VMName `
                    -Credential $credential -DisablePasswordAuthentication | `
                    Set-AzVMSourceImage -PublisherName "Canonical" -Offer "UbuntuServer" `
                        -Skus "18.04-LTS" -Version "latest" | `
                    Set-AzVMOSDisk -Name "$VMName-disk" -CreateOption "FromImage" | Out-Null
                    
                # copy local SSH public key to VM
                $sshkey = Get-Content "$env:USERPROFILE\.ssh\id_rsa.pub"
                Add-AzVMSshPublicKey -VM $vm -KeyData $sshkey `
                    -Path "/home/$($Credential.Username)/.ssh/authorized_keys" | Out-Null
            }
            elseif ($OperatingSystem.StartsWith("Windows")) {
                # get the self-signed certificate for Windows PCs
                $cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name "win-crt" -ErrorAction "SilentlyContinue"
                if (-not $cert) {
                    $cert = New-AzLabSelfSignedDomainCert -ResourceGroupName $ResourceGroupName `
                        -KeyVaultName $KeyVaultName -CertPassword $CertPassword -Domain $Domain `
                        -Name "winbox-crt"
                }

                # choose the right disk image
                if ($OperatingSystem -eq "WindowsServer") {
                    $pub = "MicrosoftWindowsServer"
                    $offer = "WindowsServer"
                    $sku = "2019-Datacenter"
                } else {
                    $pub = "MicrosoftWindowsDesktop"
                    $offer = "Windows-10"
                    $sku = "rs5-enterprise"
                }

                # note that the ProvisionVMAgent switch is required as per
                # https://docs.microsoft.com/en-us/powershell/module/az.compute/set-azvmoperatingsystem
                $vm | Set-AzVMOperatingSystem -Windows -ComputerName $VMName -WinRMHttps `
                    -Credential $Credential -WinRMCertificateUrl $cert.SecretId -ProvisionVMAgent | `
                    Set-AzVMSourceImage -PublisherName $pub -Offer $offer `
                        -Skus $sku -Version "latest" | `
                    Set-AzVMOSDisk -Name "$VMName-disk" -CreateOption "FromImage" | `
                    Add-AzVMSecret -SourceVaultId $kv.ResourceId -CertificateStore "My" `
                        -CertificateUrl $cert.SecretId | Out-Null
            }

            # disable boot diagnostics
            $vm | Set-AzVMBootDiagnostic -Disable | Out-Null

            # create the VM
            $vm | New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction "Stop" | Out-Null
            Write-Information "$OperatingSystem VM $VMName created." -InformationAction "Continue"
        }
    }
}

function Install-AzLabApps {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $VMNames,

        [Parameter()]
        [switch] $InstallSysmon,

        [Parameter()]
        [switch] $InstallAtomicRedTeam
    )

    process {
        foreach ($VMName in $VMNames) {
            $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -ErrorAction "Stop"
            $winvm = $vm.OSProfile.WindowsConfiguration

            if ($InstallSysmon) {
                if ($winvm) {
                    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
                        -CommandId "RunPowerShellScript" -ScriptPath ".\install-sysmon.ps1"
                }
            }

            if ($InstallAtomicRedTeam) {
                if ($winvm) {
                    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName `
                        -CommandId "RunPowerShellScript" -ScriptPath ".\install-atomicredteam.ps1"
                }
            }
        }
    }
}

function Remove-AzLabVM {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $VMNames
    )
    
    process {
        foreach ($VMName in $VMNames) {
            $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction "SilentlyContinue"
            if ($vm) {
                # get all resources associated with the VM (they all share the same prefix)
                $res = Get-AzResource -ResourceGroupName $ResourceGroupName -Name "$VMName*"

                # determine the order in which they are removed
                $indices = @(
                    [array]::IndexOf($res.Name, $VMName),
                    [array]::IndexOf($res.Name, "$VMName-nic"),
                    [array]::IndexOf($res.Name, "$VMName-pip"),
                    [array]::IndexOf($res.Name, "$VMName-disk")
                )

                # remove each resource if found
                foreach ($idx in $indices) {
                    if ($idx -ge 0) {
                        Remove-AzResource -ResourceId $res[$idx].Id -Force | Out-Null
                    }
                }
            }
        }
    }
}

function New-AzLabSelfSignedDomainCert {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $ResourceGroupName = $AzGlobals.ResourceGroup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $KeyVaultName = $AzGlobals.KeyVault,

        [Parameter()]
        [System.Security.SecureString] $CertPassword,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Domain = $AzGlobals.Domain,

        [Parameter()]
        [string] $FilePath,

        [Parameter()]
        [string] $CertStoreLocation = "cert:\CurrentUser\My"
    )
    
    begin {
        # defaults
        if (-not $FilePath) { $FilePath = ".\$Name.pfx" }
        if (-not $CertPassword) {
            $CertPassword = Read-Host -Prompt "Enter the certificate password" -AsSecureString
        }
    }
    
    process {
        # create a certificate for all domain PCs and write it to a file
        $cert = New-SelfSignedCertificate -DnsName "*.$Domain" `
            -CertStoreLocation $CertStoreLocation
        Export-PfxCertificate -Cert "$CertStoreLocation\$($cert.Thumbprint)" `
            -FilePath $FilePath -Password $CertPassword | Out-Null
        
        # import into key vault
        $cert = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $Name `
            -FilePath $FilePath -Password $CertPassword -ErrorAction "Stop"

        return $cert
    }
}
