<#
.SYNOPSIS
  Email Domain Security Scanner (SPF/DKIM/DMARC). Read-only DNS checks.

.DESCRIPTION
  Checks SPF, DMARC and DKIM for a domain and prints PASS/WARN/FAIL with fixes.
  Optional CSV/HTML exports for sharing evidence.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
  [string]$Domain,
  [string]$Server,
  [string[]]$DkimSelectors = @('selector1','selector2'),
  [string]$OutputPath = (Split-Path -Parent $MyInvocation.MyCommand.Path),
  [switch]$Html,
  [switch]$Csv
)

function Resolve-Record {
  param([string]$Name,[ValidateSet('TXT','CNAME')][string]$Type,[string]$Server)
  try{
    $p=@{Name=$Name;Type=$Type;ErrorAction='Stop'}; if($Server){$p['Server']=$Server}
    Resolve-DnsName @p
  }catch{ $null }
}

function Find-SPF {
  param([string]$Domain,[string]$Server)
  $txt=Resolve-Record -Name $Domain -Type TXT -Server $Server
  if(-not $txt){ return @{Present=$false;Raw=@();Valid=$false;Issues=@('No TXT records found (SPF missing)')} }
  $spfTxt=@(); foreach($r in $txt){ foreach($s in $r.Strings){ if($s -match '^v=spf1'){ $spfTxt+=$s } } }
  if($spfTxt.Count -eq 0){ return @{Present=$false;Raw=$txt.Strings;Valid=$false;Issues=@('No v=spf1 record found')} }
  $issues=@(); $valid=$true; if($spfTxt.Count -gt 1){ $issues+='Multiple SPF records found (should be ONE). Merge them.'; $valid=$false }
  $spf=$spfTxt[0]
  if($spf -notmatch 'v=spf1'){ $issues+='SPF version tag missing'; $valid=$false }
  if($spf -notmatch '(-all|~all|\?all)'){ $issues+='Missing terminal qualifier (~all or -all)'; $valid=$false }
  if($spf.Length -gt 255){ $issues+='SPF string exceeds 255 chars.'; $valid=$false }
  @{Present=$true;Raw=@($spfTxt);Valid=$valid;Issues=$issues}
}

function Parse-DmarcTags {
  param([string]$txt)
  $map=@{}; $pairs=$txt -split ';' | % { $_.Trim() } | ? { $_ }
  foreach($p in $pairs){ if($p -match '^(?<k>[a-zA-Z0-9]+)=(?<v>.+)$'){ $map[$matches.k.ToLower()]=$matches.v.Trim() } }
  $map
}

function Find-DMARC {
  param([string]$Domain,[string]$Server)
  $name="_dmarc.$Domain"; $txt=Resolve-Record -Name $name -Type TXT -Server $Server
  if(-not $txt){ return @{Present=$false;Raw=@();Valid=$false;Policy='none';Issues=@('DMARC record not found')} }
  $dmarcTxt=@(); foreach($r in $txt){ foreach($s in $r.Strings){ if($s -match '^v=DMARC1'){ $dmarcTxt+=$s } } }
  if($dmarcTxt.Count -eq 0){ return @{Present=$false;Raw=$txt.Strings;Valid=$false;Policy='none';Issues=@('No v=DMARC1 record found')} }
  $issues=@(); $valid=$true; $rec=$dmarcTxt[0]; $tags=Parse-DmarcTags -txt $rec
  if(-not $tags.ContainsKey('p')){ $issues+='Policy "p" missing (none/quarantine/reject).'; $valid=$false }
  $policy=$tags['p']
  if($policy -notin @('none','quarantine','reject')){ $issues+='Invalid policy value for "p".'; $valid=$false }
  if(-not $tags.ContainsKey('rua')){ $issues+='Missing "rua" (aggregate reports). Add a monitored mailbox.' }
  @{Present=$true;Raw=@($rec);Valid=$valid;Policy=$policy;Issues=$issues;Tags=$tags}
}

function Find-DKIM {
  param([string]$Domain,[string[]]$Selectors,[string]$Server)
  $results=@()
  foreach($s in $Selectors){
    $host="{0}._domainkey.{1}" -f $s,$Domain
    $txt=Resolve-Record -Name $host -Type TXT -Server $Server
    $cname=Resolve-Record -Name $host -Type CNAME -Server $Server
    $present=$false;$valid=$false;$mode='None';$issues=@();$raw=@()
    if($txt){ $present=$true;$mode='TXT';$vals=@(); foreach($r in $txt){ $vals+=$r.Strings }; $raw=$vals
      $dkim=($vals | ? { $_ -match '^v=DKIM1' -or $_ -match 'p=' }) -join ''
      if($dkim -match 'p='){ $valid=$true } else { $issues+='DKIM TXT found but no public key (p=) detected.' }
    } elseif($cname){ $present=$true;$mode='CNAME';$raw=@($cname.NameHost);$valid=$true }
    else { $issues+='No TXT or CNAME found for selector.' }
    $results += [pscustomobject]@{ Selector=$s; Host=$host; Present=$present; Mode=$mode; Valid=$valid; Raw=($raw -join ' '); Issues=($issues -join '; ') }
  }
  $results
}

function Assess {
  param($Spf,$Dmarc,$DkimObjs)
  $items=@()
  $spfStatus= if(-not $Spf.Present){'FAIL'} elseif($Spf.Valid){'PASS'} else {'WARN'}
  $spfFix=@(); if(-not $Spf.Present){$spfFix+='Publish a single SPF TXT: v=spf1 <includes/mechanisms> ~all'}
  if($Spf.Issues.Count -gt 0){ $spfFix+=$Spf.Issues }
  $items += [pscustomobject]@{ Control='SPF'; Status=$spfStatus; Detail=($Spf.Raw -join ' | '); Fix=($spfFix -join '; ') }

  $dStatus= if(-not $Dmarc.Present){'FAIL'} elseif($Dmarc.Valid){'PASS'} else {'WARN'}
  $dFix=@(); if(-not $Dmarc.Present){$dFix+='Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:reports@<YOUR_DOMAIN>'} else {
    if($Dmarc.Policy -eq 'none'){ $dFix+='Start with p=none + rua, then plan move to p=quarantine/reject after monitoring.' }
    if($Dmarc.Issues.Count -gt 0){ $dFix+=$Dmarc.Issues }
  }
  $items += [pscustomobject]@{ Control='DMARC'; Status=$dStatus; Detail=($Dmarc.Raw -join ' | '); Fix=($dFix -join '; ') }

  foreach($dk in $DkimObjs){
    $dkStatus= if(-not $dk.Present){'FAIL'} elseif($dk.Valid){'PASS'} else {'WARN'}
    $dkFix=@(); if(-not $dk.Present){ $dkFix+="Publish DKIM for $($dk.Selector) (TXT key or CNAME to provider)." }
    elseif(-not $dk.Valid){ $dkFix+="Record exists but incomplete: $($dk.Issues)" }
    $items += [pscustomobject]@{ Control="DKIM ($($dk.Selector))"; Status=$dkStatus; Detail=$dk.Raw; Fix=($dkFix -join '; ') }
  }
  $items
}

Write-Host "Email Domain Security Scanner — $Domain" -ForegroundColor Cyan
if($Server){ Write-Host "DNS Server: $Server" -ForegroundColor DarkGray }
Write-Host "Checking SPF..." -ForegroundColor Yellow
$spf=Find-SPF -Domain $Domain -Server $Server
Write-Host "Checking DMARC..." -ForegroundColor Yellow
$dmarc=Find-DMARC -Domain $Domain -Server $Server
Write-Host "Checking DKIM selectors: $($DkimSelectors -join ', ')" -ForegroundColor Yellow
$dkim=Find-DKIM -Domain $Domain -Selectors $DkimSelectors -Server $Server

$results=Assess -Spf $spf -Dmarc $dmarc -DkimObjs $dkim

$overall='PASS'
foreach($r in $results){
  $color='Green'; if($r.Status -eq 'FAIL'){ $color='Red'; $overall='FAIL' }
  elseif($r.Status -eq 'WARN' -and $overall -ne 'FAIL'){ $color='Yellow'; $overall='WARN' }
  Write-Host ("{0,-16} {1,-7} {2}" -f $r.Control,$r.Status,$r.Detail) -ForegroundColor $color
}
Write-Host ("Overall: {0}" -f $overall) -ForegroundColor Cyan

$timestamp=(Get-Date).ToString('yyyyMMdd-HHmm')
$base=Join-Path $OutputPath ("EmailAuth-{0}-{1}" -f $Domain,$timestamp)

if($Csv){
  $csvPath="$base.csv"
  $results | Select-Object Control,Status,Detail,Fix | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath
  Write-Host "CSV saved: $csvPath" -ForegroundColor Green
}
if($Html){
  $htmlPath="$base.html"
  $style=@"
  <style>
    body { font-family: system-ui, Segoe UI, Roboto, Arial; margin: 24px; }
    h1 { font-size: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
    th { background: #f7f9fc; text-align: left; }
    .PASS { color: #0e8a00; font-weight: 600; }
    .WARN { color: #b8860b; font-weight: 600; }
    .FAIL { color: #b00020; font-weight: 600; }
    .meta { color: #555; margin-bottom: 8px; }
  </style>
"@
  $rows = $results | ForEach-Object {
    "<tr><td>$($_.Control)</td><td class='$($_.Status)'>$($_.Status)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Fix))</td></tr>"
  } | Out-String
  $html=@"
  <html><head><meta charset='utf-8'>$style</head><body>
    <h1>Email Domain Security Scanner — $Domain</h1>
    <div class='meta'>Scanned: $(Get-Date) &nbsp;|&nbsp; DKIM selectors: $($DkimSelectors -join ', ')</div>
    <table>
      <thead><tr><th>Control</th><th>Status</th><th>Detail</th><th>Recommended Fix</th></tr></thead>
      <tbody>$rows</tbody>
    </table>
    <p class='meta'>Notes: Start DMARC with <code>p=none</code> and <code>rua</code>, then move to <code>p=quarantine</code> or <code>p=reject</code>.</p>
  </body></html>
"@
  $html | Out-File -Encoding UTF8 -FilePath $htmlPath
  Write-Host "HTML saved: $htmlPath" -ForegroundColor Green
}

$results
