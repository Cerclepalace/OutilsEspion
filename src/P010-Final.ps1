[CmdletBinding()]
param(
    [string]$InputRoot = (Join-Path $PSScriptRoot '..\evidence\P009'),
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\evidence\P010')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$required = @(
    'controls.json'
)
$inputs = foreach ($name in $required) {
    $path = Join-Path $InputRoot $name
    if (Test-Path $path) {
        [pscustomobject]@{
            file = $name
            status = 'PRESENT'
            sha256 = (Get-FileHash $path -Algorithm SHA256).Hash
        }
    } else {
        [pscustomobject]@{
            file = $name
            status = 'MISSING'
            sha256 = $null
        }
    }
}

$controlsPath = Join-Path $InputRoot 'controls.json'
$controlCount = 0
if (Test-Path $controlsPath) {
    $data = Get-Content $controlsPath -Raw | ConvertFrom-Json
    $controlCount = @($data.controls).Count
}

$result = [pscustomobject]@{
    schema = 'P010'
    generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    pipeline = @('P001','P002','P003','P004','P005','P006','P007','P008','P009','P010')
    inputs = @($inputs)
    control_count = $controlCount
    decision = 'NOT_VALIDATED'
    mutation_policy = 'NO_AUTOMATIC_REMEDIATION'
    authorization_required_for_action = $true
    note = 'P010 aggregates pipeline metadata only; it does not declare compromise and does not perform remediation.'
}

$result | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputRoot 'final.json') -Encoding UTF8
