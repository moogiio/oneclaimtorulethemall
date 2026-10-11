// The PowerShell part of the export script that does the work: looks up
// AD groups, previews, asks, backs up, creates trusts, applies and rolls
// back. export.js puts the data ($Groups, $Trusts) in front of it.
// Pure ESM; everything here is printable ASCII.

// Runs inside `. { }`: pasted into a console, the whole script is one
// command, so Read-Host gets the admin's answer and not the next pasted line.
export const ENGINE = String.raw`
# Nothing below needs editing.
function Get-OneClaimLines([string]$Text) {
  $Text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

# Ordered line diff (longest common subsequence) with two lines of context,
# so the admin sees where in the rules each line was removed or added.
function Show-OneClaimDiff($Old, $New) {
  $n = $Old.Count
  $m = $New.Count
  if ($n * $m -gt 250000) {
    Write-Host '    Too many lines to compare. The new rules:'
    foreach ($Line in $New) { Write-Host "    + $Line" -ForegroundColor Green }
    return
  }
  $L = New-Object 'int[,]' -ArgumentList ($n + 1), ($m + 1)
  for ($i = $n - 1; $i -ge 0; $i--) {
    for ($j = $m - 1; $j -ge 0; $j--) {
      if ($Old[$i] -ceq $New[$j]) { $L[$i, $j] = $L[($i + 1), ($j + 1)] + 1 }
      else { $L[$i, $j] = [Math]::Max($L[($i + 1), $j], $L[$i, ($j + 1)]) }
    }
  }
  $Ops = New-Object System.Collections.Generic.List[object]
  $i = 0
  $j = 0
  while ($i -lt $n -or $j -lt $m) {
    if ($i -lt $n -and $j -lt $m -and $Old[$i] -ceq $New[$j]) { $Ops.Add(@(' ', $Old[$i])); $i++; $j++ }
    elseif ($j -lt $m -and ($i -ge $n -or $L[$i, ($j + 1)] -ge $L[($i + 1), $j])) { $Ops.Add(@('+', $New[$j])); $j++ }
    else { $Ops.Add(@('-', $Old[$i])); $i++ }
  }
  $Shown = -1
  for ($k = 0; $k -lt $Ops.Count; $k++) {
    $Near = $false
    for ($d = [Math]::Max(0, $k - 2); $d -le [Math]::Min($Ops.Count - 1, $k + 2); $d++) { if ($Ops[$d][0] -ne ' ') { $Near = $true } }
    if (-not $Near) { continue }
    if ($k -gt $Shown + 1) { Write-Host '      ...' }
    $Shown = $k
    if ($Ops[$k][0] -eq '-') { Write-Host "    - $($Ops[$k][1])" -ForegroundColor Red }
    elseif ($Ops[$k][0] -eq '+') { Write-Host "    + $($Ops[$k][1])" -ForegroundColor Green }
    else { Write-Host "      $($Ops[$k][1])" }
  }
  if ($Shown -lt $Ops.Count - 1) { Write-Host '      ...' }
}

# Every text inside an access control policy's parameters, whatever their shape.
function Get-OneClaimStrings($Value) {
  if ($null -eq $Value) { return }
  if ($Value -is [string]) { return $Value }
  if ($Value -is [System.Collections.IDictionary]) { foreach ($Item in $Value.Values) { Get-OneClaimStrings $Item }; return }
  if ($Value -is [System.Collections.IEnumerable]) { foreach ($Item in $Value) { Get-OneClaimStrings $Item }; return }
  [string]$Value
}

# True when the policy parameters AD FS reports hold exactly the wanted
# groups, by name or by the SID step 1 looked up: AD FS may report either.
function Test-OneClaimGroups($Value, $Wanted) {
  $Wanted = @($Wanted | Sort-Object -Unique)
  $Known = @{}
  foreach ($Group in $Wanted) {
    $Known[$Group] = $Group
    if ($GroupSids.ContainsKey($Group)) { $Known[$GroupSids[$Group]] = $Group }
  }
  $Found = @{}
  foreach ($Text in @(Get-OneClaimStrings $Value | Where-Object { $_ })) {
    if (-not $Known.ContainsKey($Text)) { return $false }
    $Found[$Known[$Text]] = $true
  }
  return $Found.Count -eq $Wanted.Count
}

# Creates a trust AD FS does not have yet, from metadata or by hand.
function New-OneClaimTrust($Item) {
  $Create = $Item.Trust.Create
  $Params = @{ Name = $Item.Trust.Name }
  $File = $null
  if ($Create.MetadataUrl) {
    $Params.MetadataUrl = $Create.MetadataUrl
  } elseif ($Create.MetadataXml) {
    # AD FS reads metadata from a file, so the metadata goes to a temporary one.
    $File = Join-Path ([System.IO.Path]::GetTempPath()) ('oneclaim-' + [guid]::NewGuid().ToString() + '.xml')
    [System.IO.File]::WriteAllText($File, $Create.MetadataXml, (New-Object System.Text.UTF8Encoding $false))
    $Params.MetadataFile = $File
  } else {
    $Params.Identifier = @($Create.Identifier)
    if ($Create.SamlUrl) { $Params.SamlEndpoint = @(New-AdfsSamlEndpoint -Binding 'POST' -Protocol 'SAMLAssertionConsumer' -Uri $Create.SamlUrl) }
    else { $Params.WSFedEndpoint = $Create.WsFedUrl }
  }
  $Add = $Item.Trust.Add
  try {
    & $Add @Params -ErrorAction Stop
  } finally {
    if ($File) { Remove-Item -LiteralPath $File -Force -ErrorAction SilentlyContinue }
  }
  Write-Host "Created $($Item.Trust.Name)." -ForegroundColor Green
}

function Set-OneClaimTrust($Item) {
  $Set = $Item.Trust.Set
  $Name = $Item.Trust.Name
  if ($Item.Create) { New-OneClaimTrust $Item }
  foreach ($Step in $Item.Steps) {
    if ($Step.Property -eq 'IssuanceAuthorizationRules') { continue }
    $Params = @{ TargetName = $Name }
    $Params[$Step.Property] = $Step.Rules
    & $Set @Params -ErrorAction Stop
  }
  foreach ($Step in $Item.Steps) {
    if ($Step.Property -ne 'IssuanceAuthorizationRules') { continue }
    # AD FS 2016 and later ignore authorization rules while a policy is set.
    if ($Item.Before.AccessControlPolicyName) {
      & $Set -TargetName $Name -AccessControlPolicyName $null -ErrorAction Stop
    }
    & $Set -TargetName $Name -IssuanceAuthorizationRules $Step.Rules -ErrorAction Stop
  }
  if ($Item.Policy) {
    $Policy = $Item.Trust.Policy
    $Params = @{ TargetName = $Name; AccessControlPolicyName = $Policy.Name }
    if ($Policy.Groups.Count) {
      # Microsoft documents the groups as a list of DOMAIN\Group names. Tools
      # that set built-in policies use @{ GroupParameter = ... }, so that form
      # is tried when AD FS rejects the list.
      $Params.AccessControlPolicyParameters = @($Policy.Groups)
      try {
        & $Set @Params -ErrorAction Stop
      } catch {
        Write-Warning "AD FS did not take the groups as a list ($_). Trying them as GroupParameter."
        $Params.AccessControlPolicyParameters = @{ GroupParameter = @($Policy.Groups) }
        & $Set @Params -ErrorAction Stop
      }
    } else {
      # A policy without groups gets no leftover parameters from the old one.
      if ($Item.Before.AccessControlPolicyParameters) { $Params.AccessControlPolicyParameters = $null }
      & $Set @Params -ErrorAction Stop
    }
    $Get = $Item.Trust.Get
    $After = & $Get -Name $Name -ErrorAction Stop
    if ([string]$After.AccessControlPolicyName -ne $Policy.Name) {
      throw "AD FS did not keep the access control policy '$($Policy.Name)' on $Name."
    }
    if ($Policy.Groups.Count) {
      $Reported = @(Get-OneClaimStrings $After.AccessControlPolicyParameters | Where-Object { $_ })
      # A group policy without groups would let nobody in.
      if (-not $Reported.Count) { throw "AD FS kept no groups for the access control policy '$($Policy.Name)' on $Name." }
      if (-not (Test-OneClaimGroups $After.AccessControlPolicyParameters $Policy.Groups)) {
        Write-Warning "Check the groups of the access control policy on $Name. AD FS reports: $($Reported -join ', ')"
      }
    }
  }
}

function Restore-OneClaimAccess($Item) {
  $Set = $Item.Trust.Set
  $Name = $Item.Trust.Name
  $Before = $Item.Before
  if ($Before.AccessControlPolicyName) {
    # The policy takes over again; AD FS ignores the rules while it is set.
    $Params = @{ TargetName = $Name; AccessControlPolicyName = $Before.AccessControlPolicyName }
    # The old parameters go back, and groups this script set are cleared.
    if ($Before.AccessControlPolicyParameters -or ($Item.Policy -and $Item.Trust.Policy.Groups.Count)) {
      $Params.AccessControlPolicyParameters = $Before.AccessControlPolicyParameters
    }
    & $Set @Params -ErrorAction Stop
    return
  }
  # The trust had authorization rules: take off the policy this script set.
  if ($Item.Policy) { & $Set -TargetName $Name -AccessControlPolicyName $null -ErrorAction Stop }
  & $Set -TargetName $Name -IssuanceAuthorizationRules $Before.IssuanceAuthorizationRules -ErrorAction Stop
}

function Restore-OneClaimTrust($Item) {
  $Set = $Item.Trust.Set
  $Name = $Item.Trust.Name
  if ($Item.Create) {
    # A trust this script created is removed again, if it got that far.
    $Get = $Item.Trust.Get
    $Remove = $Item.Trust.Remove
    if (& $Get -Name $Name -ErrorAction Stop) { & $Remove -TargetName $Name -Confirm:$false -ErrorAction Stop }
    return
  }
  $Access = [bool]$Item.Policy
  foreach ($Step in $Item.Steps) {
    if ($Step.Property -eq 'IssuanceAuthorizationRules') { $Access = $true; continue }
    $Params = @{ TargetName = $Name }
    $Params[$Step.Property] = $Item.Before.($Step.Property)
    & $Set @Params -ErrorAction Stop
  }
  if ($Access) { Restore-OneClaimAccess $Item }
}

# 0. In a WID farm only the primary server can change trusts.
$Sync = $null
try { $Sync = Get-AdfsSyncProperties -ErrorAction Stop } catch { }
if ($Sync -and $Sync.Role -eq 'SecondaryComputer') {
  throw "This is a secondary AD FS server, so nothing was changed. Run the script on the primary server ($($Sync.PrimaryComputerName))."
}

# 1. AD group names to SIDs. Stops before any change if a group is not found.
$GroupSids = @{}
foreach ($Group in $Groups) {
  try {
    $Sid = ([System.Security.Principal.NTAccount]$Group).Translate([System.Security.Principal.SecurityIdentifier]).Value
  } catch {
    throw "The AD group '$Group' was not found, so nothing was changed. Fix the name in OneClaimToRuleThemAll and export again. ($($_.Exception.Message))"
  }
  # Best effort: users and computers never match a group SID claim. Groups,
  # built-in and foreign security principals (other forests) pass.
  $Class = @()
  try { $Class = @(([adsi]"LDAP://<SID=$Sid>").Properties['objectClass']) } catch { }
  if ($Class -contains 'user' -or $Class -contains 'computer') {
    throw "'$Group' is not a group in AD, so nothing was changed. Fix the name in OneClaimToRuleThemAll and export again."
  }
  $GroupSids[$Group] = $Sid
  Write-Host "$Group is $Sid"
}
foreach ($Trust in $Trusts) {
  foreach ($Step in $Trust.Steps) {
    foreach ($Group in $Groups) {
      $Step.Rules = $Step.Rules.Replace('Value == {SID of ' + $Group + '}', 'Value == "' + $GroupSids[$Group] + '"')
    }
  }
}

# 2. Show what would change. Nothing is changed yet.
$OneClaimBefore = [ordered]@{}
$Plan = @()
$Missing = @()
$Clash = @()
foreach ($Trust in $Trusts) {
  Write-Host ''
  Write-Host "$($Trust.Name) ($($Trust.Kind))" -ForegroundColor Cyan
  $Get = $Trust.Get
  $Current = & $Get -Name $Trust.Name -ErrorAction Stop
  $Create = $false
  if (-not $Current -and $Trust.Create -and $Trust.Create.Identifier) {
    # AD FS allows each identifier once; a trust under another name may have it.
    $Taken = & $Get -Identifier $Trust.Create.Identifier -ErrorAction SilentlyContinue
    if ($Taken) {
      Write-Warning "AD FS already has a $($Trust.Kind) with the identifier $($Trust.Create.Identifier), named '$($Taken.Name)', so this one is skipped. Use that name in OneClaimToRuleThemAll, or remove that trust first."
      $Clash += $Trust.Name
      continue
    }
  }
  if (-not $Current -and $Trust.Create) {
    # A new trust starts with no rules and no policy, so everything below is added.
    $Create = $true
    if ($Trust.Create.MetadataUrl) { Write-Host "  Not in AD FS yet, so it is created from the metadata at $($Trust.Create.MetadataUrl)" -ForegroundColor Yellow }
    elseif ($Trust.Create.MetadataXml) { Write-Host "  Not in AD FS yet, so it is created from the metadata file in this script, for $($Trust.Create.Identifier)" -ForegroundColor Yellow }
    else { Write-Host "  Not in AD FS yet, so it is created for $($Trust.Create.Identifier)" -ForegroundColor Yellow }
    $Current = [pscustomobject]@{ AccessControlPolicyName = $null; AccessControlPolicyParameters = $null; IssuanceAuthorizationRules = ''; IssuanceTransformRules = ''; AcceptanceTransformRules = '' }
  }
  if (-not $Current) {
    Write-Warning "There is no $($Trust.Kind) with this name in AD FS, so it is skipped. The name must match AD FS Management."
    $Missing += $Trust.Name
    continue
  }
  $Changed = @()
  foreach ($Step in $Trust.Steps) {
    $Old = @(Get-OneClaimLines $Current.($Step.Property))
    $New = @(Get-OneClaimLines $Step.Rules)
    $Policy = if ($Step.Property -eq 'IssuanceAuthorizationRules') { $Current.AccessControlPolicyName }
    $Same = ($Old -join [char]10) -ceq ($New -join [char]10)
    if ($Same -and -not $Policy) {
      Write-Host "  $($Step.Title): no change"
      continue
    }
    Write-Host "  $($Step.Title): changes" -ForegroundColor Yellow
    if ($Policy) { Write-Host "    The access control policy '$Policy' is replaced by these rules" }
    if (-not $Same) { Show-OneClaimDiff $Old $New }
    $Changed += $Step
  }
  $SetPolicy = $false
  if ($Trust.Policy) {
    $Now = [string]$Current.AccessControlPolicyName
    $Wanted = $Trust.Policy.Name
    $Have = @(Get-OneClaimStrings $Current.AccessControlPolicyParameters | Where-Object { $_ } | Sort-Object -Unique)
    $Want = @($Trust.Policy.Groups | Sort-Object -Unique)
    $For = { param($List) if ($List.Count) { ' for ' + ($List -join ', ') } else { '' } }
    if ($Now -eq $Wanted -and (Test-OneClaimGroups $Current.AccessControlPolicyParameters $Want)) {
      Write-Host '  Who gets access: no change'
    } else {
      Write-Host '  Who gets access: changes' -ForegroundColor Yellow
      if ($Now) { Write-Host "    - access control policy '$Now'$(& $For $Have)" -ForegroundColor Red }
      elseif (-not $Create) { Write-Host '    - the authorization rules of the trust' -ForegroundColor Red }
      Write-Host "    + access control policy '$Wanted'$(& $For $Want)" -ForegroundColor Green
      $SetPolicy = $true
    }
  }
  if ($Changed.Count -or $SetPolicy -or $Create) {
    $Before = $Current | Select-Object AccessControlPolicyName, AccessControlPolicyParameters, IssuanceAuthorizationRules, IssuanceTransformRules, AcceptanceTransformRules
    if (-not $Create) { $OneClaimBefore["$($Trust.Kind): $($Trust.Name)"] = $Before }
    $Plan += [pscustomobject]@{ Trust = $Trust; Steps = $Changed; Policy = $SetPolicy; Before = $Before; Create = $Create }
  }
}

# 3. Ask before changing anything.
Write-Host ''
if ($Missing.Count) { Write-Warning ('Not found in AD FS, so skipped: ' + ($Missing -join ', ')) }
if ($Clash.Count) { Write-Warning ('Identifier already taken in AD FS, so skipped: ' + ($Clash -join ', ')) }
if (-not $Plan.Count) {
  if ($Missing.Count -or $Clash.Count) { Write-Host 'Nothing was changed.' }
  else { Write-Host 'Nothing to change, the trusts already have these rules.' -ForegroundColor Green }
  return
}
$Answer = Read-Host "Apply the changes above to $($Plan.Count) trust(s)? Type Y to apply, anything else cancels"
if ($Answer -ne 'Y') {
  Write-Host 'Cancelled, nothing was changed.'
  return
}
# A copy of the current settings that outlives this script. New trusts have
# nothing to save.
$Backup = $null
if ($OneClaimBefore.Count) {
  $Backup = Join-Path ([IO.Path]::GetTempPath()) ('OneClaimToRuleThemAll-before-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.xml')
  $OneClaimBefore | Export-Clixml -Path $Backup -ErrorAction Stop
  Write-Host "The current settings are saved in $Backup"
}

# 4. Apply. If anything fails, every trust changed so far gets its previous settings back.
$Done = @()
foreach ($Item in $Plan) {
  try {
    Set-OneClaimTrust $Item
    $Done += $Item
    Write-Host "Applied to $($Item.Trust.Name)." -ForegroundColor Green
  } catch {
    $Failure = $_
    Write-Warning "Applying to $($Item.Trust.Name) failed: $Failure"
    Write-Warning 'Putting the previous settings back on every trust this script changed.'
    $NotRestored = @()
    $NotRemoved = @()
    foreach ($Undo in @($Item) + $Done) {
      try { Restore-OneClaimTrust $Undo } catch {
        if ($Undo.Create) { $NotRemoved += "$($Undo.Trust.Name): $_" } else { $NotRestored += "$($Undo.Trust.Name): $_" }
      }
    }
    if ($NotRestored.Count) {
      Write-Error ('Putting the previous settings back failed for ' + ($NotRestored -join '; ') + '. Check these trusts now. ' +
        'Their previous settings are saved in ' + $Backup + ', read them with: Import-Clixml ''' + $Backup + '''')
    }
    if ($NotRemoved.Count) {
      Write-Error ('Removing the trusts this script created failed for ' + ($NotRemoved -join '; ') + '. Remove them by hand, ' +
        'in AD FS Management or with ' + $Item.Trust.Remove + ' -TargetName <name>.')
    }
    if (-not $NotRestored.Count -and -not $NotRemoved.Count) {
      Write-Warning 'The previous settings are back in place.'
    }
    throw $Failure
  }
}
$Created = @($Done | Where-Object { $_.Create }).Count
Write-Host "Done. The new rules are applied to $($Done.Count) trust(s)$(if ($Created) { ", $Created of them created" })." -ForegroundColor Green
}`.trimStart();
