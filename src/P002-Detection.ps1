[CmdletBinding()]
param([string]$InputRoot=(Join-Path $PSScriptRoot '..\evidence\P001'),[string]$OutputRoot=(Join-Path $PSScriptRoot '..\evidence\P002'))
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$in=Join-Path $InputRoot 'raw\inventory.json'; if(!(Test-Path $in)){throw 'P001 inventory missing'}
$data=Get-Content $in -Raw | ConvertFrom-Json;$findings=[System.Collections.Generic.List[object]]::new()
foreach($r in $data.records){$v=if($null -eq $r.value){''}else{$r.value|Out-String};$signal=($v -match '(?i)(powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|encodedcommand|javascript:)');if($signal){$findings.Add([pscustomobject]@{finding_id=('P002-{0:D5}'-f ($findings.Count+1));evidence_id=$r.evidence_id;category=$r.category;source=$r.source;signal='REQUIRES_REVIEW';reason='Execution or scripting indicator observed in collected data';value=$r.value})}}
[pscustomobject]@{schema='P002';input_sha256=(Get-FileHash $in -Algorithm SHA256).Hash;finding_count=$findings.Count;findings=$findings;validation='NOT_VALIDATED'}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $OutputRoot 'detections.json') -Encoding UTF8
