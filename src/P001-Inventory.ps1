[CmdletBinding()]
param([string]$OutputRoot = (Join-Path $PSScriptRoot '..\evidence\P001'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$raw=Join-Path $OutputRoot 'raw'; New-Item -ItemType Directory -Force -Path $raw | Out-Null
$records=[System.Collections.Generic.List[object]]::new()
function Add-Record([string]$Category,[string]$Source,$Value,[string]$Status='COLLECTED',[string]$Error=''){$records.Add([pscustomobject]@{evidence_id=('P001-{0:D5}'-f ($records.Count+1));category=$Category;source=$Source;collected_at_utc=(Get-Date).ToUniversalTime().ToString('o');status=$Status;value=$Value;error=$Error})}
function Read-Safe([string]$Category,[string]$Source,[scriptblock]$Action){try{Add-Record $Category $Source (& $Action)}catch{Add-Record $Category $Source $null 'COLLECTOR_ERROR' $_.Exception.Message}}
Read-Safe system 'Get-CimInstance Win32_OperatingSystem' {Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime}
Read-Safe system 'Get-CimInstance Win32_ComputerSystem' {Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,Domain,PartOfDomain,TotalPhysicalMemory,UserName}
Read-Safe firmware 'Get-CimInstance Win32_BIOS' {Get-CimInstance Win32_BIOS | Select Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber}
Read-Safe cpu 'Get-CimInstance Win32_Processor' {Get-CimInstance Win32_Processor | Select Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed}
Read-Safe storage 'Get-CimInstance Win32_DiskDrive' {Get-CimInstance Win32_DiskDrive | Select Model,InterfaceType,MediaType,Size,SerialNumber}
Read-Safe identity 'Get-CimInstance Win32_UserAccount' {Get-CimInstance Win32_UserAccount | Select Name,Domain,Disabled,LocalAccount,Status}
Read-Safe network 'Get-NetAdapter' {Get-NetAdapter | Select Name,InterfaceDescription,Status,MacAddress,LinkSpeed}
Read-Safe network 'Get-NetIPConfiguration' {Get-NetIPConfiguration}
Read-Safe network 'Get-DnsClientServerAddress' {Get-DnsClientServerAddress}
Read-Safe network 'Get-NetRoute' {Get-NetRoute | Select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric}
Read-Safe network 'netsh winhttp show proxy' {netsh winhttp show proxy}
Read-Safe security 'Get-MpComputerStatus' {Get-MpComputerStatus | Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntispywareEnabled,AntivirusSignatureLastUpdated}
Read-Safe security 'Get-NetFirewallProfile' {Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction}
Read-Safe execution 'Get-Process' {Get-Process | Select Id,ProcessName,Path,StartTime,CPU}
Read-Safe execution 'Get-Service' {Get-Service | Select Name,DisplayName,Status,StartType}
Read-Safe persistence 'Get-ScheduledTask' {Get-ScheduledTask | Select TaskPath,TaskName,State,Author,Description}
Read-Safe persistence 'Win32_StartupCommand' {Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User}
Read-Safe persistence 'Winlogon registry' {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select Userinit,Shell}
Read-Safe persistence 'AppInit registry' {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select AppInit_DLLs,LoadAppInit_DLLs}
Read-Safe network 'Get-NetTCPConnection' {Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess}
Read-Safe host 'hosts' {Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop}
$inventory=[pscustomobject]@{schema='P001';mutation_policy='READ_ONLY';record_count=$records.Count;records=$records}
$json=$inventory | ConvertTo-Json -Depth 8
$path=Join-Path $raw 'inventory.json'; [IO.File]::WriteAllText($path,$json,(New-Object Text.UTF8Encoding($false)))
$hash=(Get-FileHash $path -Algorithm SHA256).Hash
[pscustomobject]@{schema='P001-MANIFEST';generated_at_utc=(Get-Date).ToUniversalTime().ToString('o');host=$env:COMPUTERNAME;evidence_file='raw/inventory.json';sha256=$hash;record_count=$records.Count;validation='NOT_VALIDATED'} | ConvertTo-Json | Set-Content (Join-Path $OutputRoot 'manifest.json') -Encoding UTF8
