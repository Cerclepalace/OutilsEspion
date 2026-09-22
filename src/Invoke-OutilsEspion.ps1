[CmdletBinding()]
param(
    [string]$OutputRoot = $(Join-Path $PSScriptRoot '..\evidence'),
    [switch]$NoEncryption
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$started = Get-Date
$root = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $root | Out-Null
$raw = Join-Path $root 'raw'
New-Item -ItemType Directory -Force -Path $raw | Out-Null

function Save-Json([string]$Name, [object]$Data) {
    $path = Join-Path $raw $Name
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Save-Text([string]$Name, [scriptblock]$Block) {
    $path = Join-Path $raw $Name
    try { & $Block 2>&1 | Out-String | Set-Content -LiteralPath $path -Encoding UTF8 }
    catch { "COLLECTOR_ERROR: $($_.Exception.Message)" | Set-Content -LiteralPath $path -Encoding UTF8 }
    return $path
}

$items = @()
$items += Save-Json 'system.json' ([pscustomobject]@{
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture)
})
$items += Save-Json 'processes.json' (Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate)
$items += Save-Json 'services.json' (Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName)
$items += Save-Json 'scheduled_tasks.json' (Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,Actions,Triggers)
$items += Save-Text 'startup.txt' { Get-CimInstance Win32_StartupCommand | Format-List * }
$items += Save-Text 'network.txt' { Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize }
$items += Save-Text 'defender.txt' { Get-MpComputerStatus | Format-List *; Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | Format-List }
$items += Save-Text 'proxy.txt' { netsh winhttp show proxy; Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL }
$items += Save-Text 'hosts.txt' { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue }
$items += Save-Text 'ifeo.txt' { reg query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s }
$items += Save-Text 'winlogon.txt' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' }
$items += Save-Text 'appinit.txt' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select-Object AppInit_DLLs,LoadAppInit_DLLs }
$items += Save-Text 'wmi_persistence.txt' {
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Format-List *
    Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Format-List *
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Format-List *
}

$manifest = foreach ($path in $items) {
    $f = Get-Item -LiteralPath $path
    [pscustomobject]@{
        path = $f.FullName.Substring($root.Length).TrimStart('\','/')
        size = $f.Length
        sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        collected_at = $started.ToUniversalTime().ToString('o')
    }
}
$manifestPath = Join-Path $root 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

if (-not $NoEncryption -and $PSVersionTable.PSVersion.Major -ge 7) {
    $secure = Read-Host 'Evidence passphrase (not stored)' -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $pass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($plain)
        $salt = [Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        $nonce = [Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
        $key = [Security.Cryptography.Rfc2898DeriveBytes]::new($pass,$salt,600000,[Security.Cryptography.HashAlgorithmName]::SHA256).GetBytes(32)
        $input = [IO.File]::ReadAllBytes($manifestPath)
        $cipher = [byte[]]::new($input.Length)
        $tag = [byte[]]::new(16)
        $gcm = [Security.Cryptography.AesGcm]::new($key,16)
        $gcm.Encrypt($nonce,$input,$cipher,$tag)
        [IO.File]::WriteAllBytes((Join-Path $root 'manifest.enc'), ($salt + $nonce + $tag + $cipher))
        Remove-Item -LiteralPath $manifestPath -Force
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($plain)
        if ($null -ne $pass) { $pass = $null }
        if ($null -ne $key) { [Array]::Clear($key,0,$key.Length) }
    }
}

[pscustomobject]@{
    status = 'COLLECTION_COMPLETE'
    started_utc = $started.ToUniversalTime().ToString('o')
    finished_utc = (Get-Date).ToUniversalTime().ToString('o')
    elapsed_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds,2)
    output = $root
    network_mode = 'OFFLINE_REQUIRED'
    persistence = 'NONE_CREATED'
    validation = 'NOT_VALIDATED'
} | ConvertTo-Json | Write-Output
