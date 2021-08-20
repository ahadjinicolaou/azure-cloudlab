# uses config from Olaf Hartong's sysmon-modular project
# https://github.com/olafhartong/sysmon-modular
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonConfigUrl = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$SysmonFolder = "C:\sysmon"
$SysmonArchivePath = "$SysmonFolder\sysmon.zip"
$SysmonConfigPath = "$SysmonFolder\sysmonconfig.xml"

# abort if there's nothing to do
$exists = tasklist | Select-String "sysmon"
if ($exists) {
    Write-Information -Message "Sysmon is already installed."
    return
}

# download and extract sysmon
New-Item -Path $SysmonFolder -ItemType "directory"
Invoke-WebRequest $SysmonUrl -OutFile $SysmonArchivePath
Expand-Archive -LiteralPath $SysmonArchivePath -DestinationPath $SysmonFolder

# download and extract sysmon config
Invoke-WebRequest $SysmonConfigUrl -Outfile $SysmonConfigPath

# install sysmon
& "$SysmonFolder\Sysmon64.exe" -accepteula -i $SysmonConfigPath
if (tasklist | Select-String "sysmon") {
    Write-Information -Message "Sysmon installed successfully."
}
