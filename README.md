#### 🚧 Under construction -- tread carefully! 🚧

# Overview

The general goal of this project is to better understand malicious network activity through system log analysis. To that end, this suite of PowerShell functions can be used to provision and configure a virtualized environment that supports the following activities:
* simulation of hostile network behaviors using Atomic Red Team
* collection of Sysmon and Syslog event logs to observe network activity
* threat detection and analysis using Azure Sentinel.

An accompanying writeup for this work can be found [here](https://www.remotelycurious.net/post/threatlab/).

# Requirements

* Azure Subscription
* Azure Key Vault
* PowerShell with [*Az*](https://docs.microsoft.com/en-us/powershell/azure) and [*Az.SecurityInsights*](https://docs.microsoft.com/en-us/powershell/module/az.securityinsights) modules

# Installation

To run this under your own subscription, you will need to modify the variables within `set-azlab-globals.ps1`. At a minimum, you will need to set `KeyVault` and `KeyVaultResGroup` to match your own environment. Further, if you reside outside of the US, it is probably a good idea to set `Location` to a closer region.

#### Initialize Azure global variables
```bash
.\set-azlab-globals.ps1
```

#### Install the virtual network
```bash
Install-AzLabRemoteAccessVNet
```

#### Create a Windows Server VM
```bash
$vmname = "winsrv"
$user = "adminshmadmin"
$cred = Get-Credential -UserName $user
New-AzLabVM -OperatingSystem "WindowsServer" -VMNames $vmname `
    -Credential $cred -CertPassword $cred.Password 
```

#### Install prerequisite applications
```bash
Install-AzLabApps -VMNames $vmname -InstallSysmon -InstallAtomicRedTeam
```

#### Install the Log Analytics workspace
```bash
Install-AzLabLogAnalyticsWorkspace
```

#### Connect the VM to the workspace
```bash
Connect-VMsToLogAnalytics -VMNames $vmname
```

#### Connect Log Analytics to Sentinel
```bash
Connect-AzLogAnalyticsToSentinel
```

#### Create alert rules 

This step depends on what you have implemented in your workspace. For example, let's assume "Sysmon" refers to a simple Kusto function:
```bash
Event | where Source == "Microsoft-Windows-Sysmon"
```

We can then use this to create a Sysmon rule to detect signs of credential dumping:
```bash
New-AzSentinelScheduledAlertRule -Severity "High" -DisplayName "T1059.001-1 (Mimikatz)" `
    -Query "Sysmon | where EventID == 10 and TargetImage endswith 'lsass.exe'"
```

# Usage

The [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) testing framework is used to initiate hostile network activity on a remote host whose logs are being monitored. After launching an attack, the idea is to look for traces of the attack within system event logs, with the help of Azure Sentinel and Log Analytics.

> To be clear, this framework makes use of live malware to simulate the operations of a threat actor. It is not something you should use carelessly. Please don't use this code unless you know what you are doing.

#### Start a remote session
```bash
$vmip = (Get-AzPublicIpAddress -ResourceGroupName $AzGlobals.ResourceGroup `
    -Name "$vmname-pip").IpAddress
Enter-PSSession -ComputerName $vmip -UseSSL -Credential $cred `
    -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck)
```

Before we can simulate our bad behavior, Windows Defender will need to be put to bed.

#### Turn off Windows Defender
```bash
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Load the testing framework
```bash
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

After identifying a threat technique that you want to investigate, such as [PowerShell scripting](https://attack.mitre.org/techniques/T1059/001/), download any prerequisite files before running the test suite.

#### Download supporting files
```bash
Invoke-AtomicTest T1059.001 -GetPrereqs
```

#### Trigger Mimikatz
```bash
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

If all has gone well, Azure Sentinel will eventually detect the attack and generate an alert.
