# abort if nothing to do
$exists = Test-Path -Path "C:\AtomicRedTeam"
if ($exists) {
    Write-Information -Message "Atomic Red Team is already installed."
    return
}

# install NuGet package provider
Find-PackageProvider -Name "NuGet" -ForceBootstrap -IncludeDependencies

# install ART
Invoke-Expression (Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force

# disable Internet Explorer's "first run" wizard check
# without this, ART can't download verified binaries
# reference: https://tinyurl.com/878dkb7r
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 1 -Force
