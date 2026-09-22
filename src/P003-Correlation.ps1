[CmdletBinding()]param([string]$InputRoot=(Join-Path $PSScriptRoot '..\evidence\P002'),[string]$OutputRoot=(Join-Path $PSScriptRoot '..\evidence\P003'))
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';New-Item -ItemType Directory -Force -Path $OutputRoot|Out-Null
$d=Get-Content (Join-Path $InputRoot 'detections.json') -Raw|ConvertFrom-Json;$groups=$d.findings|Group-Object category|ForEach-Object{[pscustomobject]@{category=$_.Name;count=$_.Count;finding_ids=@($_.Group.finding_id)}}
[pscustomobject]@{schema='P003';source_sha256=(Get-FileHash (Join-Path $InputRoot 'detections.json') -Algorithm SHA256).Hash;correlations=@($groups);validation='NOT_VALIDATED'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputRoot 'correlations.json') -Encoding UTF8
