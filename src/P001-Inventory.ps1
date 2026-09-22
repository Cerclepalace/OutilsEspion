[CmdletBinding()]
param(
    [string]$OutputRoot = $(Join-Path $PSScriptRoot '..\evidence\P001'),
    [switch]$IncludeCommandLines
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$started = Get-Date
$root = [IO.Path]::GetFullPath($OutputRoot)
$raw = Join-Path $root 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null

$records = New-Object System.Collections.Generic.List[object]

function Add-Record {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [object]$Value,
        [string]$Status = 'OBSERVED',
        [string]$Error = $null
    )

    $records.Add([pscustomobject]@{
        evidence_id = $Id
        category = $Category
        source = $Source
        collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        status = $Status
        value = $Value
        error = $Error
    })
}

function Invoke-ReadOnly {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [scriptblock]$Collector
    )

    try {
        Add-Record -Id $Id -Category $Category -Source $Source -Value (& $Collector)
    }
    catch {
        Add-Record -Id $Id -Category $Category -Source $Source -Value $null -Status 'COLLECTOR_ERROR' -Error $_.Exception.Message
    }
}

Invoke-ReadOnly 'P001-0001' 'execution' 'PowerShell' { [pscustomobject]@{
    version = $PSVersionTable.PSVersion.ToString()
    edition = $PSVersionTable.PSEdition
    process_architecture = $PSVersionTable.OS
} }

Invoke-ReadOnly 'P001-0002' 'identity' 'environment' { [pscustomobject]@{
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    user_domain = $env:USERDOMAIN
    logon_server = $env:LOGONSERVER
} }

Invoke-ReadOnly 'P001-0003' 'system' 'Win32_OperatingSystem' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime }
Invoke-ReadOnly 'P001-0004' 'firmware' 'Win32_BIOS' { Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,SerialNumber,ReleaseDate }
Invoke-ReadOnly 'P001-0005' 'hardware' 'Win32_ComputerSystem' { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType,TotalPhysicalMemory,Domain,PartOfDomain }
Invoke-ReadOnly 'P001-0006' 'cpu' 'Win32_Processor' { Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed }
Invoke-ReadOnly 'P001-0007' 'storage' 'Win32_DiskDrive' { Get-CimInstance Win32_DiskDrive | Select-Object Model,Manufacturer,InterfaceType,MediaType,Size,SerialNumber }
Invoke-ReadOnly 'P001-0008' 'network' 'Win32_NetworkAdapterConfiguration' { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,MACAddress,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder }
Invoke-ReadOnly 'P001-0009' 'network' 'Get-NetIPConfiguration' { Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer }
Invoke-ReadOnly 'P001-0010' 'network' 'WinHTTP proxy' { netsh winhttp show proxy 2>&1 | Out-String }
Invoke-ReadOnly 'P001-0011' 'network' 'Internet Settings proxy' { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL }
Invoke-ReadOnly 'P001-0012' 'security' 'Windows Defender status' { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated }
Invoke-ReadOnly 'P001-0013' 'security' 'Windows Firewall profiles' { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }
Invoke-ReadOnly 'P001-0014' 'process' 'Win32_Process' {
    if ($IncludeCommandLines) {
        Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate
    } else {
        Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate
    }
}
Invoke-ReadOnly 'P001-0015' 'service' 'Win32_Service' { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName }
Invoke-ReadOnly 'P001-0016' 'scheduled_task' 'Get-ScheduledTask' { Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,Actions,Triggers }
Invoke-ReadOnly 'P001-0017' 'startup' 'Win32_StartupCommand' { Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User }
Invoke-ReadOnly 'P001-0018' 'persistence' 'Winlogon' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell,Userinit,Notify,Taskman }
Invoke-ReadOnly 'P001-0019' 'persistence' 'AppInit' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select-Object AppInit_DLLs,LoadAppInit_DLLs }
Invoke-ReadOnly 'P001-0020' 'persistence' 'IFEO' { reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s 2>&1 | Out-String }
Invoke-ReadOnly 'P001-0021' 'persistence' 'WMI subscriptions' {
    [pscustomobject]@{
        filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
        consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
        bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    }
}
Invoke-ReadOnly 'P001-0022' 'network' 'active TCP connections' { Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess }
Invoke-ReadOnly 'P001-0023' 'hosts' 'Windows hosts file' { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue }

$recordsPath = Join-Path $raw 'inventory.json'
$records | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $recordsPath -Encoding UTF8

$manifest = [pscustomobject]@{
    module = 'P001'
    module_version = '0.1.0'
    host = $env:COMPUTERNAME
    started_utc = $started.ToUniversalTime().ToString('o')
    finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    record_count = $records.Count
    evidence_file = 'raw/inventory.json'
    sha256 = (Get-FileHash -LiteralPath $recordsPath -Algorithm SHA256).Hash
    mutation_policy = 'READ_ONLY'
    validation = 'NOT_VALIDATED'
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Encoding UTF8

[pscustomobject]$manifest | ConvertTo-Json -Depth 8 | Write-Output
