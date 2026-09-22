[CmdletBinding()]param([string]$InputRoot=(Join-Path $PSScriptRoot '..\evidence\P001'),[string]$OutputRoot=(Join-Path $PSScriptRoot '..\evidence\P006'))
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';New-Item -ItemType Directory -Force -Path $OutputRoot|Out-Null
$d=Get-Content (Join-Path $InputRoot 'raw\inventory.json') -Raw|ConvertFrom-Json;$events=@($d.records)|ForEach-Object{[pscustomobject]@{evidence_id=$_.evidence_id;category=$_.category;collected_at_utc=$_.collected_at_utc;status=$_.status;source=$_.source}}|Sort-Object collected_at_utc
[pscustomobject]@{schema='P006';events=$events;ordering='UTC_ASC';validation='NOT_VALIDATED'}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputRoot 'timeline.json') -Encoding UTF8
