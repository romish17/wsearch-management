param(
  [switch]$Force,
  [string]$ProfilesRoot = "C:\Users"
)

$excluded = @("Default","Default User","Public","All Users","Administrator","Administrateur")

Write-Host "=== Cleanup Windows Search per-user (Roaming) ==="
Write-Host ("Mode: " + ($(if($Force){"APPLIQUER (-Force)"} else {"DRY-RUN (simulation)"})))
Write-Host "ProfilesRoot: $ProfilesRoot`n"

if (-not (Test-Path $ProfilesRoot)) { throw "Chemin introuvable: $ProfilesRoot" }

# Regex SID de domaine classique
$sidRegex = '^S-1-5-21-\d+-\d+-\d+-\d+$'

$targets = New-Object System.Collections.Generic.List[string]

$profiles = Get-ChildItem -Path $ProfilesRoot -Directory -ErrorAction Stop |
  Where-Object { $excluded -notcontains $_.Name }

foreach ($p in $profiles) {
  $appsRoot = Join-Path $p.FullName "AppData\Roaming\Microsoft\Search\Data\Applications"
  if (-not (Test-Path $appsRoot)) { continue }

  # On ne supprime que les dossiers SID
  $sidDirs = Get-ChildItem -Path $appsRoot -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $sidRegex }

  foreach ($d in $sidDirs) {
    # Optionnel: ne garder que ceux qui contiennent une base EDB quelque part
    $edb = Get-ChildItem -Path $d.FullName -Recurse -Force -ErrorAction SilentlyContinue -Filter *.edb | Select-Object -First 1
    if ($edb) {
      $targets.Add($d.FullName) | Out-Null
      Write-Host ("[MATCH] {0} (EDB détectée: {1})" -f $d.FullName, $edb.FullName)
    }
  }
}

$targets = $targets | Sort-Object -Unique

if ($targets.Count -eq 0) {
  Write-Host "Aucune base EDB per-user trouvée sous Roaming\Microsoft\Search\Data\Applications."
  return
}

Write-Host "`nDossiers à nettoyer: $($targets.Count)"
$targets | ForEach-Object { Write-Host " - $_" }

if (-not $Force) {
  Write-Host "`nDRY-RUN terminé. Relance avec -Force pour supprimer."
  return
}

Write-Host "`nSuppression..."
foreach ($t in $targets) {
  try {
    # Prise de propriété / droits (souvent nécessaire)

    Remove-Item -Path $t -Recurse -Force -ErrorAction Stop
    Write-Host "OK: $t"
  } catch {
    Write-Warning ("KO: {0} -> {1}" -f $t, $_.Exception.Message)
  }
}

Write-Host "Terminé."
