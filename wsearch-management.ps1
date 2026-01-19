#Requires -Version 5.1
<#
WindowsSearchTuner.ps1 - WPF GUI (Adaptive + DB Manager + Logs + Index Status + Maintenance)
- Tab 1: Tweaks Windows Search / FSLogix (si détecté)
- Tab 2: Gestion des bases Windows Search (Global Windows.edb / Per-user *.edb)
- Tab 3: Visualisation des logs Windows Search (Event Viewer)
- Tab 4: Statut de l'indexation (éléments indexés, emplacements, taille)
- Tab 5: Maintenance et réparation (diagnostic, rebuild index, suppression catalogues per-user, USN)
#>

# -------------------------
# Admin check + relaunch
# -------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = "powershell.exe"
    $psi.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    $psi.Verb      = "runas"
    try { [Diagnostics.Process]::Start($psi) | Out-Null } catch { }
    exit
}

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

# -------------------------
# System detection
# -------------------------
$os = Get-CimInstance Win32_OperatingSystem
$osCaption = $os.Caption
$osVersion = $os.Version
$osBuild   = [int]$os.BuildNumber
$osProductType = $os.ProductType   # 1=Workstation, 2=DC, 3=Server
$isServer = ($osProductType -ne 1)
$isModernBuild = ($osBuild -ge 17763) # 1809+

# -------------------------
# Registry helpers
# -------------------------
function Ensure-Key([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Get-RegDword([string]$Path, [string]$Name) {
    if (-not (Test-Path $Path)) { return $null }
    try {
        $p = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains $Name) { return [int]$p.$Name }
        return $null
    } catch { return $null }
}

function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Remove-RegValue([string]$Path, [string]$Name) {
    if (Test-Path $Path) {
        try { Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop | Out-Null } catch { }
    }
}

function Backup-RegistryKeyToRegFile([string]$RegKey, [string]$OutFile) {
    & reg.exe export $RegKey $OutFile /y | Out-Null
}

# -------------------------
# Profile Type Detection (FSLogix, UPD, Roaming)
# -------------------------

# FSLogix detection
$fslogixRegPresent = (Test-Path "HKLM:\SOFTWARE\FSLogix") -or (Test-Path "HKLM:\SOFTWARE\Policies\FSLogix")
$fslogixServicePresent = $false
try {
    $frx = Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue
    if ($frx) { $fslogixServicePresent = $true }
} catch { }
$hasFSLogix = ($fslogixRegPresent -or $fslogixServicePresent)

# UPD (User Profile Disks) detection - RDS feature
$hasUPD = $false
try {
    # Check RDS cluster settings
    $rdsClusterKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings"
    if (Test-Path $rdsClusterKey) {
        $props = Get-ItemProperty $rdsClusterKey -ErrorAction SilentlyContinue
        if ($props.UvhdEnabled -eq 1) { $hasUPD = $true }
        if ($props.UvhdShareUrl) { $hasUPD = $true }
    }

    # Also check policies
    $rdsPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (Test-Path $rdsPolicyKey) {
        $props = Get-ItemProperty $rdsPolicyKey -ErrorAction SilentlyContinue
        if ($props.fEnableUserDataDisk -eq 1) { $hasUPD = $true }
    }
} catch { }

# Roaming Profiles detection
$hasRoamingProfiles = $false
$roamingProfilePath = ""
try {
    # Check if roaming profiles are configured via GPO
    $profilePolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if (Test-Path $profilePolicyKey) {
        $props = Get-ItemProperty $profilePolicyKey -ErrorAction SilentlyContinue
        if ($props.EnableProfileQuota) { $hasRoamingProfiles = $true }
    }

    # Check Terminal Services profile path
    $tsPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (Test-Path $tsPolicyKey) {
        $props = Get-ItemProperty $tsPolicyKey -ErrorAction SilentlyContinue
        if ($props.WFProfilePath -and $props.WFProfilePath -like "\\*") {
            $hasRoamingProfiles = $true
            $roamingProfilePath = $props.WFProfilePath
        }
    }

    # Check default user profile for roaming indicator
    $profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    if (Test-Path $profileListKey) {
        $profiles = Get-ChildItem $profileListKey -ErrorAction SilentlyContinue
        foreach ($p in $profiles) {
            $profileProps = Get-ItemProperty $p.PSPath -ErrorAction SilentlyContinue
            if ($profileProps.CentralProfile -and $profileProps.CentralProfile -like "\\*") {
                $hasRoamingProfiles = $true
                break
            }
        }
    }
} catch { }

# Determine profile type priority: FSLogix > UPD > Roaming > Local
$detectedProfileType = "Local"
if ($hasFSLogix) { $detectedProfileType = "FSLogix" }
elseif ($hasUPD) { $detectedProfileType = "UPD" }
elseif ($hasRoamingProfiles) { $detectedProfileType = "Roaming" }

# Current selected profile type (can be changed by user)
$script:selectedProfileType = $detectedProfileType

# -------------------------
# Profile-based Recommendations
# -------------------------
$ProfileRecommendations = @{
    "Local" = @{
        Description = "Profils locaux - Configuration standard"
        EnablePerUserCatalog = ""  # Pas de recommandation spécifique
        DisableBackoff = "0"
        ConnectedSearchUseWeb = "0"
        EnableDynamicContentInWSB = "0"
        PreventRemoteQueries = "1"
        DisableRemovableDriveIndexing = "1"
        AllowCloudSearch = "0"
        AllowSearchToUseLocation = "0"
        RoamSearch = ""  # N/A
        Notes = "Configuration standard pour postes fixes. L'indexation per-user n'est généralement pas nécessaire."
    }
    "FSLogix" = @{
        Description = "FSLogix - Optimisé pour conteneurs VHD/VHDX"
        EnablePerUserCatalog = "1"  # Recommandé pour isoler les index dans le conteneur
        DisableBackoff = "0"  # Garder le backoff pour réduire la charge
        ConnectedSearchUseWeb = "0"
        EnableDynamicContentInWSB = "0"
        PreventRemoteQueries = "1"
        DisableRemovableDriveIndexing = "1"
        AllowCloudSearch = "0"
        AllowSearchToUseLocation = "0"
        RoamSearch = "0"  # Désactivé sur OS modernes (>= 1809)
        Notes = "Per-user catalog isolé dans le VHD. RoamSearch désactivé car géré nativement. Backoff actif pour réduire I/O."
    }
    "UPD" = @{
        Description = "User Profile Disks (RDS) - Optimisé pour VHD RDS"
        EnablePerUserCatalog = "1"  # Isoler dans le UPD
        DisableBackoff = "0"
        ConnectedSearchUseWeb = "0"
        EnableDynamicContentInWSB = "0"
        PreventRemoteQueries = "1"
        DisableRemovableDriveIndexing = "1"
        AllowCloudSearch = "0"
        AllowSearchToUseLocation = "0"
        RoamSearch = ""  # N/A pour UPD
        Notes = "Index per-user stocké dans le UPD. Minimise l'impact sur le serveur RDS."
    }
    "Roaming" = @{
        Description = "Profils itinérants - Éviter l'indexation per-user"
        EnablePerUserCatalog = "0"  # IMPORTANT: Éviter les catalogues per-user dans profils roaming
        DisableBackoff = "0"
        ConnectedSearchUseWeb = "0"
        EnableDynamicContentInWSB = "0"
        PreventRemoteQueries = "1"
        DisableRemovableDriveIndexing = "1"
        AllowCloudSearch = "0"
        AllowSearchToUseLocation = "0"
        RoamSearch = ""  # N/A
        Notes = "ATTENTION: Les catalogues per-user dans les profils roaming causent des problèmes de synchronisation et de corruption. Utiliser l'index global uniquement."
    }
}

# -------------------------
# Settings catalog (Adaptive)
# -------------------------
function Get-ProfileRecommendation([string]$SettingName) {
    $profile = $script:selectedProfileType
    $recs = $ProfileRecommendations[$profile]
    if ($recs -and $recs.ContainsKey($SettingName)) {
        return $recs[$SettingName]
    }
    return ""
}

$RawSettings = @(
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="DisableBackoff (Indexer backoff)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="DisableBackoff"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "DisableBackoff" }
        Description="0 = Backoff actif (moins agressif, économise ressources). 1 = backoff désactivé (plus agressif)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="ConnectedSearchUseWeb (Web results)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="ConnectedSearchUseWeb"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "ConnectedSearchUseWeb" }
        Description="0 = coupe résultats Web/Bing (économise bande passante)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="EnableDynamicContentInWSB (Search highlights)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="EnableDynamicContentInWSB"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "EnableDynamicContentInWSB" }
        Description="0 = désactive contenus dynamiques/highlights (économise ressources)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="PreventRemoteQueries (Remote queries)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="PreventRemoteQueries"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "PreventRemoteQueries" }
        Description="1 = empêche requêtes à distance sur l'index (sécurité)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="DisableRemovableDriveIndexing"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="DisableRemovableDriveIndexing"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "DisableRemovableDriveIndexing" }
        Description="1 = pas d'indexation sur supports amovibles (économise ressources)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="AllowCloudSearch"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="AllowCloudSearch"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "AllowCloudSearch" }
        Description="0 = coupe la recherche cloud (économise bande passante)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="AllowSearchToUseLocation"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="AllowSearchToUseLocation"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "AllowSearchToUseLocation" }
        Description="0 = désactive usage localisation (confidentialité)."
    },

    [pscustomobject]@{
        Category="Windows Search (Base)"
        DisplayName="EnablePerUserCatalog"
        KeyPath="HKLM:\SOFTWARE\Microsoft\Windows Search"
        ValueName="EnablePerUserCatalog"
        Type="DWORD"
        Policy=$false
        RequiresFSLogix=$false
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "EnablePerUserCatalog" }
        Description="1 = index par utilisateur. ATTENTION: Pas recommandé avec profils roaming classiques!"
    },

    # FSLogix only if present
    [pscustomobject]@{
        Category="FSLogix"
        DisplayName="RoamSearch (Profiles)"
        KeyPath="HKLM:\SOFTWARE\FSLogix\Profiles"
        ValueName="RoamSearch"
        Type="DWORD"
        Policy=$false
        RequiresFSLogix=$true
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "RoamSearch" }
        Description="0 = désactivé (recommandé sur OS >= 1809). 1 = roaming de l'index via FSLogix."
    },
    [pscustomobject]@{
        Category="FSLogix"
        DisplayName="RoamSearch (ODFC Policies)"
        KeyPath="HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
        ValueName="RoamSearch"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$true
        RequiresUPD=$false
        RecommendedDynamic={ Get-ProfileRecommendation "RoamSearch" }
        Description="0 = désactivé (recommandé sur OS >= 1809). Appliqué via GPO."
    }
)

function Get-ApplicableSettings {
    $list = @()
    foreach ($s in $RawSettings) {
        if ($s.RequiresFSLogix -and -not $script:hasFSLogix) { continue }
        $list += $s
    }
    return $list
}
$Settings = Get-ApplicableSettings

function Build-UiRows {
    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
    foreach ($s in $Settings) {
        $cur = Get-RegDword $s.KeyPath $s.ValueName
        $curTxt = if ($null -eq $cur) { "(Absent)" } else { "$cur" }

        $rec = ""
        try { $rec = & $s.RecommendedDynamic } catch { $rec = "" }

        $rows.Add([pscustomobject]@{
            Category         = $s.Category
            Name             = $s.DisplayName
            KeyPath          = $s.KeyPath
            ValueName        = $s.ValueName
            Current          = $curTxt
            Recommended      = $rec
            Desired          = ""
            Description      = $s.Description
            IsPolicy         = [bool]$s.Policy
        })
    }
    return $rows
}

# -------------------------
# DB / Index paths + Scan
# -------------------------
function Get-GlobalSearchDbPath {
    return "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
}

function Get-PerUserSearchRoot([string]$ProfilePath) {
    return Join-Path $ProfilePath "AppData\Roaming\Microsoft\Search\Data\Applications"
}

function Try-ResolveSamFromSid([string]$sid) {
    try {
        $objSid = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $nt = $objSid.Translate([System.Security.Principal.NTAccount])
        return $nt.Value
    } catch {
        return ""
    }
}

function Scan-SearchDatabases {
    $result = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    # Global DB
    $globalPath = Get-GlobalSearchDbPath
    if (Test-Path $globalPath) {
        $fi = Get-Item $globalPath -ErrorAction SilentlyContinue
        $result.Add([pscustomobject]@{
            Scope="Global"
            User="(Machine)"
            SID=""
            Path=$fi.FullName
            SizeMB=[math]::Round($fi.Length/1MB,2)
            LastWrite=$fi.LastWriteTime
        })
    } else {
        $result.Add([pscustomobject]@{
            Scope="Global"
            User="(Machine)"
            SID=""
            Path="(Introuvable) $globalPath"
            SizeMB=0
            LastWrite=$null
        })
    }

    # Per-user DBs
    $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

    foreach ($p in $profiles) {
        $root = Get-PerUserSearchRoot -ProfilePath $p.FullName
        if (-not (Test-Path $root)) { continue }

        # cherche des *.edb sous Applications\SID\SID.edb (souvent)
        $edbs = Get-ChildItem $root -Recurse -Filter "*.edb" -ErrorAction SilentlyContinue
        foreach ($e in $edbs) {
            $sid = ""
            # tente de récupérer le SID depuis le chemin (dernier dossier SID)
            $parentName = Split-Path (Split-Path $e.FullName -Parent) -Leaf
            if ($parentName -match '^S-\d-\d+-.+') { $sid = $parentName }

            $user = if ($sid) { Try-ResolveSamFromSid $sid } else { $p.Name }

            $result.Add([pscustomobject]@{
                Scope="Per-User"
                User=$user
                SID=$sid
                Path=$e.FullName
                SizeMB=[math]::Round($e.Length/1MB,2)
                LastWrite=$e.LastWriteTime
            })
        }
    }

    return $result
}

function Get-WSearchStatusText {
    $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
    if (-not $svc) { return "WSearch: (Service introuvable)" }
    return "WSearch: $($svc.Status) | StartType: $((Get-CimInstance Win32_Service -Filter "Name='WSearch'").StartMode)"
}

function Restart-WSearch {
    $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "Service WSearch introuvable." }

    Set-Service -Name "WSearch" -StartupType Automatic
    Set-RegDword -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Value 1
    Restart-Service -Name "WSearch" -Force -ErrorAction Stop
}

function Stop-WSearch {
    $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "Service WSearch introuvable." }
    if ($svc.Status -eq "Running") {
        Stop-Service -Name "WSearch" -Force -ErrorAction Stop
    }
}

function Start-WSearch {
    $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "Service WSearch introuvable." }
    Start-Service -Name "WSearch" -ErrorAction Stop
}

function Remove-DbFile([string]$path) {
    if (-not (Test-Path $path)) { throw "Fichier introuvable: $path" }
    # supprime
    Remove-Item -Path $path -Force -ErrorAction Stop
}

# -------------------------
# Windows Search Logs
# -------------------------
function Get-WindowsSearchLogs {
    param(
        [int]$MaxEvents = 200,
        [string[]]$Levels = @("Error","Warning","Information"),
        [string]$FilterText = ""
    )

    $result = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    # Map level names to integers
    $levelMap = @{
        "Critical"    = 1
        "Error"       = 2
        "Warning"     = 3
        "Information" = 4
        "Verbose"     = 5
    }

    $levelNumbers = @()
    foreach ($l in $Levels) {
        if ($levelMap.ContainsKey($l)) {
            $levelNumbers += $levelMap[$l]
        }
    }

    # Provider names for Windows Search logs
    $providers = @(
        "Microsoft-Windows-Search",
        "Microsoft-Windows-Search-Core",
        "Microsoft-Windows-Search-ProfileNotify",
        "Microsoft-Windows-SearchIndexer"
    )

    $allEvents = @()

    foreach ($provider in $providers) {
        try {
            $filterXml = @"
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Application">*[System[Provider[@Name='$provider']]]</Select>
  </Query>
</QueryList>
"@
            $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            if ($events) { $allEvents += $events }
        } catch { }

        # Try the dedicated log path
        try {
            $logName = "Microsoft-Windows-Search/Admin"
            if ($provider -eq "Microsoft-Windows-Search") {
                $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                if ($events) { $allEvents += $events }
            }
        } catch { }

        # Also check Operational logs
        try {
            $logName = "Microsoft-Windows-Search/Operational"
            $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            if ($events) { $allEvents += $events }
        } catch { }
    }

    # Also get events from System log related to WSearch service
    try {
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Service Control Manager']]] and *[EventData[Data[@Name='param1']='Windows Search']]</Select>
  </Query>
</QueryList>
"@
        $events = Get-WinEvent -FilterXml $filterXml -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($events) { $allEvents += $events }
    } catch { }

    # Filter and sort
    $allEvents = $allEvents | Where-Object {
        $levelNumbers -contains $_.Level -or $levelNumbers.Count -eq 0
    }

    if (-not [string]::IsNullOrWhiteSpace($FilterText)) {
        $allEvents = $allEvents | Where-Object {
            $_.Message -like "*$FilterText*" -or
            $_.ProviderName -like "*$FilterText*"
        }
    }

    $allEvents = $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents

    foreach ($e in $allEvents) {
        $levelName = switch ($e.Level) {
            1 { "Critical" }
            2 { "Error" }
            3 { "Warning" }
            4 { "Information" }
            5 { "Verbose" }
            default { "Unknown" }
        }

        $msgText = if ([string]::IsNullOrEmpty($e.Message)) { "(Aucun message)" } else { $e.Message }
        $msgShort = ($msgText -replace "`r`n", " " -replace "`n", " ")
        if ($msgShort.Length -gt 500) { $msgShort = $msgShort.Substring(0, 500) + "..." }

        $result.Add([pscustomobject]@{
            TimeCreated  = $e.TimeCreated
            Level        = $levelName
            EventId      = $e.Id
            Source       = $e.ProviderName
            Message      = $msgShort
            FullMessage  = $msgText
        })
    }

    return $result
}

function Open-EventViewer-SearchLogs {
    try {
        # Open Event Viewer filtered to Windows Search
        Start-Process "eventvwr.msc" -ArgumentList '/c:"Microsoft-Windows-Search/Admin"' -ErrorAction SilentlyContinue
    } catch {
        # Fallback: just open Event Viewer
        Start-Process "eventvwr.msc" -ErrorAction SilentlyContinue
    }
}

function Export-LogsToCsv {
    param(
        [System.Collections.ObjectModel.ObservableCollection[Object]]$Logs,
        [string]$FilePath
    )

    $Logs | Select-Object TimeCreated, Level, EventId, Source, FullMessage |
        Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}

# -------------------------
# Windows Search Index Status
# -------------------------
function Get-SearchIndexStatus {
    $status = [pscustomobject]@{
        ServiceStatus       = "Inconnu"
        ServiceStartType    = "Inconnu"
        IndexingStatus      = "Inconnu"
        ItemsIndexed        = 0
        ItemsToIndex        = 0
        ItemsTotal          = 0
        IndexSizeMB         = 0
        LastIndexTime       = $null
        CatalogStatus       = "Inconnu"
    }

    # Service status
    try {
        $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
        if ($svc) {
            $status.ServiceStatus = $svc.Status.ToString()
            $svcConfig = Get-CimInstance Win32_Service -Filter "Name='WSearch'" -ErrorAction SilentlyContinue
            if ($svcConfig) {
                $status.ServiceStartType = $svcConfig.StartMode
            }
        }
    } catch { }

    # Try to get indexing status via SearchManager COM object
    try {
        $searchManager = New-Object -ComObject Microsoft.Search.Interop.CSearchManager
        $catalog = $searchManager.GetCatalog("SystemIndex")

        # GetCatalogStatus returns the status directly
        $pauseReason = 0
        $additionalInfo = 0
        $catalogStatus = $catalog.GetCatalogStatus([ref]$pauseReason, [ref]$additionalInfo)

        $status.CatalogStatus = switch ($catalogStatus) {
            0 { "Idle (Prêt)" }
            1 { "Paused (En pause)" }
            2 { "Recovering (Récupération)" }
            3 { "Full crawl (Indexation complète)" }
            4 { "Incremental crawl (Indexation incrémentale)" }
            5 { "Processing notifications" }
            6 { "Shutting down" }
            default { "Inconnu ($catalogStatus)" }
        }

        # Get item counts
        $status.ItemsIndexed = $catalog.NumberOfItems()

        # Release COM object
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($catalog) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($searchManager) | Out-Null
    } catch {
        # Fallback: try to get status from registry
        try {
            $statusKey = "HKLM:\SOFTWARE\Microsoft\Windows Search\CatalogNames\SystemIndex"
            if (Test-Path $statusKey) {
                $status.CatalogStatus = "Disponible (via Registry)"
            } else {
                $status.CatalogStatus = "Non disponible"
            }
        } catch {
            $status.CatalogStatus = "Erreur: $($_.Exception.Message)"
        }
    }

    # Alternative: Get status from registry/performance counters
    try {
        $perfCounter = Get-Counter "\Search Indexer(*)\*" -ErrorAction SilentlyContinue
        if ($perfCounter) {
            foreach ($sample in $perfCounter.CounterSamples) {
                if ($sample.Path -like "*documents indexed*") {
                    $status.ItemsIndexed = [int]$sample.CookedValue
                }
                if ($sample.Path -like "*documents filtered*") {
                    $status.ItemsToIndex = [int]$sample.CookedValue
                }
            }
        }
    } catch { }

    # Index size from DB file
    try {
        $globalDb = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        if (Test-Path $globalDb) {
            $fi = Get-Item $globalDb -ErrorAction SilentlyContinue
            $status.IndexSizeMB = [math]::Round($fi.Length / 1MB, 2)
            $status.LastIndexTime = $fi.LastWriteTime
        }
    } catch { }

    return $status
}

function Get-IndexedLocations {
    $locations = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    try {
        $searchManager = New-Object -ComObject Microsoft.Search.Interop.CSearchManager
        $catalog = $searchManager.GetCatalog("SystemIndex")
        $crawlScopeManager = $catalog.GetCrawlScopeManager()

        # Get roots
        $rootsEnum = $crawlScopeManager.EnumerateRoots()
        while ($true) {
            try {
                $root = $rootsEnum.Next(1, [ref]$null, [ref]$null)
                if (-not $root) { break }

                $url = $rootsEnum.URL
                $isIncluded = $crawlScopeManager.IncludedInCrawlScope($url)

                $locations.Add([pscustomobject]@{
                    Type     = "Root"
                    Path     = $url
                    Included = if ($isIncluded) { "Oui" } else { "Non" }
                    Status   = "Actif"
                })
            } catch { break }
        }

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($crawlScopeManager) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($catalog) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($searchManager) | Out-Null
    } catch {
        # Fallback: read from registry
    }

    # Fallback/additional: Read indexed locations from registry
    try {
        $scopeKey = "HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\DefaultRules"
        if (Test-Path $scopeKey) {
            $rules = Get-ChildItem $scopeKey -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                $props = Get-ItemProperty $rule.PSPath -ErrorAction SilentlyContinue
                if ($props.URL) {
                    $existing = $locations | Where-Object { $_.Path -eq $props.URL }
                    if (-not $existing) {
                        $locations.Add([pscustomobject]@{
                            Type     = "Rule"
                            Path     = $props.URL
                            Included = if ($props.Include -eq 1) { "Oui" } else { "Non" }
                            Status   = "Registry"
                        })
                    }
                }
            }
        }

        # Also check user-defined rules
        $userScopeKey = "HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\WorkingSetRules"
        if (Test-Path $userScopeKey) {
            $rules = Get-ChildItem $userScopeKey -ErrorAction SilentlyContinue
            foreach ($rule in $rules) {
                $props = Get-ItemProperty $rule.PSPath -ErrorAction SilentlyContinue
                if ($props.URL) {
                    $existing = $locations | Where-Object { $_.Path -eq $props.URL }
                    if (-not $existing) {
                        $locations.Add([pscustomobject]@{
                            Type     = "WorkingSet"
                            Path     = $props.URL
                            Included = if ($props.Include -eq 1) { "Oui" } else { "Non" }
                            Status   = "Registry"
                        })
                    }
                }
            }
        }
    } catch { }

    # Common indexed locations (hardcoded fallback)
    $commonPaths = @(
        "file:///C:\Users\",
        "file:///C:\ProgramData\Microsoft\Windows\Start Menu\",
        "iehistory://{user}",
        "mapi://{user}/"
    )

    foreach ($cp in $commonPaths) {
        $existing = $locations | Where-Object { $_.Path -like "*$($cp.Replace('file:///', '').Replace('/', '\'))*" }
        if (-not $existing -and $locations.Count -eq 0) {
            $locations.Add([pscustomobject]@{
                Type     = "Default"
                Path     = $cp
                Included = "Probable"
                Status   = "Standard"
            })
        }
    }

    return $locations
}

function Get-IndexedFileTypes {
    $fileTypes = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    try {
        # Read from registry - Persistent handlers
        $handlersKey = "HKLM:\SOFTWARE\Microsoft\Windows Search\Gathering Manager\Applications\Windows\GatheringSet\FileSystemIndex\Extensions"
        if (Test-Path $handlersKey) {
            $extensions = Get-ChildItem $handlersKey -ErrorAction SilentlyContinue
            foreach ($ext in $extensions) {
                $extName = $ext.PSChildName
                $props = Get-ItemProperty $ext.PSPath -ErrorAction SilentlyContinue

                $fileTypes.Add([pscustomobject]@{
                    Extension   = $extName
                    Handler     = if ($props.PSObject.Properties.Name -contains "ContentFilter") { $props.ContentFilter } else { "(Default)" }
                    IndexContent = if ($props.PSObject.Properties.Name -contains "IndexContent") { $props.IndexContent } else { "N/A" }
                })
            }
        }

        # Alternative: PropertyHandlers registry
        $propHandlersKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem\PropertyHandlers"
        if ((Test-Path $propHandlersKey) -and $fileTypes.Count -eq 0) {
            $extensions = Get-ChildItem $propHandlersKey -ErrorAction SilentlyContinue | Select-Object -First 50
            foreach ($ext in $extensions) {
                $extName = $ext.PSChildName
                $fileTypes.Add([pscustomobject]@{
                    Extension    = $extName
                    Handler      = "(PropertyHandler)"
                    IndexContent = "Oui"
                })
            }
        }
    } catch { }

    return $fileTypes
}

# -------------------------
# Maintenance & Repair Functions
# -------------------------
function Get-SearchDiagnostics {
    $diagnostics = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

    # Check for common error events
    $errorPatterns = @(
        @{ EventId = 7040; Description = "Catalogue corrompu"; Severity = "Critical"; Solution = "Reconstruire l'index" },
        @{ EventId = 3031; Description = "Impossible d'allouer un ID de document"; Severity = "Error"; Solution = "Reconstruire l'index ou supprimer les catalogues per-user" },
        @{ EventId = 3079; Description = "Notifications USN non actives (quota insuffisant)"; Severity = "Warning"; Solution = "Augmenter le quota USN ou reconstruire l'index" },
        @{ EventId = 3036; Description = "Erreur d'accès aux fichiers"; Severity = "Warning"; Solution = "Vérifier les permissions" },
        @{ EventId = 3083; Description = "Erreur de filtre de contenu"; Severity = "Warning"; Solution = "Réinstaller les iFilters" },
        @{ EventId = 1008; Description = "Service arrêté de manière inattendue"; Severity = "Error"; Solution = "Vérifier les logs système" }
    )

    try {
        # Check recent errors in Windows Search logs
        $recentErrors = @()

        $logNames = @(
            "Application",
            "Microsoft-Windows-Search/Admin",
            "Microsoft-Windows-Search/Operational"
        )

        foreach ($logName in $logNames) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 500 -ErrorAction SilentlyContinue |
                    Where-Object { $_.Level -le 3 -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }

                if ($events) {
                    $recentErrors += $events | Where-Object {
                        $_.ProviderName -like "*Search*" -or $_.Message -like "*Windows Search*" -or $_.Message -like "*indexer*"
                    }
                }
            } catch { }
        }

        # Group by EventId and count
        $errorGroups = $recentErrors | Group-Object Id | Sort-Object Count -Descending

        foreach ($group in $errorGroups) {
            $pattern = $errorPatterns | Where-Object { $_.EventId -eq $group.Name }
            $lastEvent = $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1

            $diagnostics.Add([pscustomobject]@{
                EventId     = $group.Name
                Count       = $group.Count
                Description = if ($pattern) { $pattern.Description } else { "Erreur Windows Search" }
                Severity    = if ($pattern) { $pattern.Severity } else { "Warning" }
                Solution    = if ($pattern) { $pattern.Solution } else { "Analyser le message d'erreur" }
                LastOccurrence = $lastEvent.TimeCreated
                Message     = if ($lastEvent.Message.Length -gt 200) { $lastEvent.Message.Substring(0, 200) + "..." } else { $lastEvent.Message }
            })
        }

        # Check for per-user catalog issues
        $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

        foreach ($p in $profiles) {
            $searchRoot = Join-Path $p.FullName "AppData\Roaming\Microsoft\Search\Data\Applications"
            if (Test-Path $searchRoot) {
                $edbs = Get-ChildItem $searchRoot -Recurse -Filter "*.edb" -ErrorAction SilentlyContinue
                foreach ($edb in $edbs) {
                    # Check if file is very large or old
                    $sizeMB = [math]::Round($edb.Length / 1MB, 2)
                    $age = (Get-Date) - $edb.LastWriteTime

                    if ($sizeMB -gt 500 -or $age.TotalDays -gt 30) {
                        $diagnostics.Add([pscustomobject]@{
                            EventId     = "PUC"
                            Count       = 1
                            Description = "Catalogue per-user potentiellement problématique"
                            Severity    = if ($sizeMB -gt 500) { "Warning" } else { "Info" }
                            Solution    = "Supprimer le catalogue per-user: $($edb.FullName)"
                            LastOccurrence = $edb.LastWriteTime
                            Message     = "User: $($p.Name) | Taille: $sizeMB MB | Âge: $([int]$age.TotalDays) jours"
                        })
                    }
                }
            }
        }

    } catch {
        $diagnostics.Add([pscustomobject]@{
            EventId     = "ERR"
            Count       = 1
            Description = "Erreur lors du diagnostic"
            Severity    = "Error"
            Solution    = "Vérifier les permissions"
            LastOccurrence = Get-Date
            Message     = $_.Exception.Message
        })
    }

    return $diagnostics
}

function Invoke-RebuildSearchIndex {
    param([switch]$Force)

    $result = @{
        Success = $false
        Message = ""
    }

    try {
        # Stop the service
        $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Stop-Service -Name "WSearch" -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
        }

        # Delete the index files
        $indexPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"
        if (Test-Path $indexPath) {
            # Backup the old index location
            $backupPath = "$indexPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

            if ($Force) {
                Remove-Item -Path "$indexPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Rename-Item -Path $indexPath -NewName $backupPath -ErrorAction Stop
            }
        }

        # Set registry to force rebuild
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Search"
        Set-ItemProperty -Path $regPath -Name "SetupCompletedSuccessfully" -Value 0 -Type DWord -ErrorAction SilentlyContinue

        # Restart the service
        Set-Service -Name "WSearch" -StartupType Automatic
        Start-Service -Name "WSearch" -ErrorAction Stop

        $result.Success = $true
        $result.Message = "Index global supprimé. Windows Search va reconstruire l'index automatiquement. Cela peut prendre plusieurs heures."

    } catch {
        $result.Message = "Erreur: $($_.Exception.Message)"

        # Try to restart the service anyway
        try {
            Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
        } catch { }
    }

    return $result
}

function Remove-PerUserCatalogs {
    param(
        [string]$UserProfile = "",
        [string]$SpecificFile = "",
        [switch]$All,
        [switch]$StopServiceFirst
    )

    $result = @{
        Success = $false
        Message = ""
        DeletedCount = 0
        FailedFiles = @()
        ServiceWasStopped = $false
    }

    try {
        # Stop WSearch service if requested (required for locked files)
        if ($StopServiceFirst) {
            $svc = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Stop-Service -Name "WSearch" -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                $result.ServiceWasStopped = $true
            }
        }

        # If specific file is provided, delete just that file
        if ($SpecificFile -and (Test-Path $SpecificFile)) {
            try {
                Remove-Item -Path $SpecificFile -Force -ErrorAction Stop
                $result.DeletedCount++
            } catch {
                $result.FailedFiles += $SpecificFile
            }
        } else {
            # Delete from profiles
            $profiles = @()

            if ($All) {
                $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }
            } elseif ($UserProfile) {
                $profiles = @(Get-Item $UserProfile -ErrorAction Stop)
            } else {
                throw "Spécifier un profil utilisateur ou utiliser -All"
            }

            foreach ($p in $profiles) {
                $searchRoot = Join-Path $p.FullName "AppData\Roaming\Microsoft\Search\Data\Applications"
                if (Test-Path $searchRoot) {
                    $edbs = Get-ChildItem $searchRoot -Recurse -Filter "*.edb" -ErrorAction SilentlyContinue

                    foreach ($edb in $edbs) {
                        try {
                            Remove-Item -Path $edb.FullName -Force -ErrorAction Stop
                            $result.DeletedCount++
                        } catch {
                            $result.FailedFiles += $edb.FullName
                        }
                    }

                    # Also try to remove the folder structure
                    try {
                        Remove-Item -Path $searchRoot -Recurse -Force -ErrorAction SilentlyContinue
                    } catch { }
                }
            }
        }

        # Restart WSearch if we stopped it
        if ($result.ServiceWasStopped) {
            Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
        }

        $result.Success = $true
        if ($result.FailedFiles.Count -gt 0) {
            $result.Message = "$($result.DeletedCount) catalogue(s) supprimé(s). $($result.FailedFiles.Count) fichier(s) n'ont pas pu être supprimés (utilisateurs connectés?)."
        } else {
            $result.Message = "$($result.DeletedCount) catalogue(s) per-user supprimé(s). Ils seront recréés à la prochaine connexion."
        }

    } catch {
        $result.Message = "Erreur: $($_.Exception.Message)"

        # Restart service if we stopped it
        if ($result.ServiceWasStopped) {
            Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
        }
    }

    return $result
}

function Get-FSLogixProfileInfo {
    <#
    .SYNOPSIS
    Récupère les informations sur les profils FSLogix montés
    #>

    $info = @{
        IsInstalled = $false
        ProfilesPath = ""
        MountedProfiles = @()
        OfflineVHDs = @()
    }

    # Check if FSLogix is installed
    $info.IsInstalled = $script:hasFSLogix

    if (-not $info.IsInstalled) {
        return $info
    }

    # Get profiles path from registry
    try {
        $profilesKey = "HKLM:\SOFTWARE\FSLogix\Profiles"
        if (Test-Path $profilesKey) {
            $props = Get-ItemProperty $profilesKey -ErrorAction SilentlyContinue
            if ($props.VHDLocations) {
                $info.ProfilesPath = $props.VHDLocations
            }
        }

        # Also check policies
        $policiesKey = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
        if (Test-Path $policiesKey) {
            $props = Get-ItemProperty $policiesKey -ErrorAction SilentlyContinue
            if ($props.VHDLocations -and -not $info.ProfilesPath) {
                $info.ProfilesPath = $props.VHDLocations
            }
        }
    } catch { }

    # Get currently mounted VHDs (frxcontext shows mounted profiles)
    try {
        $frxCmd = Get-Command "frx.exe" -ErrorAction SilentlyContinue
        if ($frxCmd) {
            $mounted = & frx.exe list 2>&1
            # Parse output to get mounted profiles
        }
    } catch { }

    # Alternative: Check for mounted VHDs via disk management
    try {
        $vhds = Get-Disk | Where-Object { $_.FriendlyName -like "*Virtual*" -or $_.Location -like "*.vhd*" }
        foreach ($vhd in $vhds) {
            $info.MountedProfiles += [pscustomobject]@{
                DiskNumber = $vhd.Number
                Location = $vhd.Location
                Size = [math]::Round($vhd.Size / 1GB, 2)
            }
        }
    } catch { }

    return $info
}

function Get-ConnectedUsers {
    <#
    .SYNOPSIS
    Liste les utilisateurs actuellement connectés
    #>

    $users = @()

    try {
        # Use query user command
        $queryResult = & query.exe user 2>&1
        if ($LASTEXITCODE -eq 0 -and $queryResult) {
            $lines = $queryResult | Select-Object -Skip 1
            foreach ($line in $lines) {
                if ($line -match '^\s*(\S+)\s+(\S+)?\s+(\d+)\s+(\S+)\s+(.+)$') {
                    $users += [pscustomobject]@{
                        Username = $Matches[1]
                        SessionName = $Matches[2]
                        SessionId = $Matches[3]
                        State = $Matches[4]
                        IdleTime = $Matches[5].Trim()
                    }
                }
            }
        }
    } catch { }

    # Alternative: Get logged on users from Win32_ComputerSystem
    if ($users.Count -eq 0) {
        try {
            $loggedOn = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
            if ($loggedOn) {
                $users += [pscustomobject]@{
                    Username = $loggedOn
                    SessionName = "Console"
                    SessionId = 1
                    State = "Active"
                    IdleTime = ""
                }
            }
        } catch { }
    }

    return $users
}

function Reset-USNJournal {
    param([string]$Volume = "C:")

    $result = @{
        Success = $false
        Message = ""
    }

    try {
        # This requires admin rights and fsutil
        $output = & fsutil usn deletejournal /n $Volume 2>&1
        Start-Sleep -Seconds 1
        $output2 = & fsutil usn createjournal m=33554432 a=4194304 $Volume 2>&1

        $result.Success = $true
        $result.Message = "Journal USN réinitialisé pour $Volume. Redémarrer le service WSearch."

    } catch {
        $result.Message = "Erreur: $($_.Exception.Message)"
    }

    return $result
}

function Repair-SearchService {
    $result = @{
        Success = $false
        Message = ""
        Steps = @()
    }

    try {
        # Step 1: Stop service
        $result.Steps += "Arrêt du service WSearch..."
        Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Step 2: Reset service configuration
        $result.Steps += "Réinitialisation de la configuration du service..."
        Set-Service -Name "WSearch" -StartupType Automatic
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Value 1 -Type DWord -ErrorAction SilentlyContinue

        # Step 3: Clear search data registry
        $result.Steps += "Nettoyage des paramètres de recherche..."
        $searchRegPath = "HKLM:\SOFTWARE\Microsoft\Windows Search"
        if (Test-Path $searchRegPath) {
            Set-ItemProperty -Path $searchRegPath -Name "SetupCompletedSuccessfully" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }

        # Step 4: Register search components
        $result.Steps += "Ré-enregistrement des composants..."
        $searchDll = "$env:SystemRoot\System32\SearchIndexer.exe"
        if (Test-Path $searchDll) {
            & $searchDll /reregister 2>&1 | Out-Null
        }

        # Step 5: Start service
        $result.Steps += "Démarrage du service WSearch..."
        Start-Service -Name "WSearch" -ErrorAction Stop

        $result.Success = $true
        $result.Message = "Réparation terminée. Le service WSearch a été redémarré."

    } catch {
        $result.Message = "Erreur lors de la réparation: $($_.Exception.Message)"

        # Try to start the service anyway
        try {
            Start-Service -Name "WSearch" -ErrorAction SilentlyContinue
        } catch { }
    }

    return $result
}

# -------------------------
# WPF UI
# -------------------------
[xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Search Tuner (Adaptive + DB)" Height="800" Width="1320"
        WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border BorderBrush="#444" BorderThickness="1" CornerRadius="6" Padding="10" Grid.Row="0" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Orientation="Vertical">
                    <TextBlock FontSize="18" FontWeight="SemiBold">Windows Search Tuner (Adaptive + DB)</TextBlock>
                    <TextBlock x:Name="TxtSystemInfo" Opacity="0.85"/>
                </StackPanel>

                <StackPanel Orientation="Horizontal" Grid.Column="1" HorizontalAlignment="Right">
                    <Button x:Name="BtnBackup" Content="Backup .reg" Margin="4" Padding="12,6"/>
                    <Button x:Name="BtnRestartWSearchTop" Content="Restart WSearch" Margin="4" Padding="12,6"/>
                    <Button x:Name="BtnOpenServices" Content="services.msc" Margin="4" Padding="12,6"/>
                </StackPanel>
            </Grid>
        </Border>

        <TabControl Grid.Row="1" x:Name="TabsMain">
            <TabItem Header="Tweaks">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <!-- Panneau sélection type de profil -->
                    <Border BorderBrush="#0078D4" BorderThickness="1" CornerRadius="6" Padding="10" Grid.Row="0" Margin="0,0,0,8" Background="#1A0078D4">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <StackPanel Orientation="Horizontal" Grid.Column="0" Grid.Row="0" VerticalAlignment="Center">
                                <TextBlock Text="Type de profil:" FontWeight="SemiBold" Margin="0,0,10,0" VerticalAlignment="Center"/>
                                <ComboBox x:Name="CmbProfileType" Width="150" Margin="0,0,15,0" VerticalAlignment="Center">
                                    <ComboBoxItem Content="Local" Tag="Local"/>
                                    <ComboBoxItem Content="FSLogix" Tag="FSLogix"/>
                                    <ComboBoxItem Content="UPD (RDS)" Tag="UPD"/>
                                    <ComboBoxItem Content="Profils itinérants" Tag="Roaming"/>
                                </ComboBox>
                                <TextBlock x:Name="TxtDetectedProfile" Opacity="0.8" VerticalAlignment="Center" Margin="0,0,20,0"/>
                            </StackPanel>

                            <TextBlock x:Name="TxtProfileDescription" Grid.Column="1" Grid.Row="0" Opacity="0.9" VerticalAlignment="Center" FontStyle="Italic"/>

                            <TextBlock x:Name="TxtProfileNotes" Grid.ColumnSpan="2" Grid.Row="1" TextWrapping="Wrap" Opacity="0.85" Margin="0,8,0,0" Foreground="#FF9800"/>
                        </Grid>
                    </Border>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="1" Margin="0,0,0,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <TextBlock Opacity="0.9" TextWrapping="Wrap">
                                Conseil: clique "Charger recommandés" puis "Appliquer tout (Desired)".
                                Utilise (Remove) pour revenir à "Non configuré" sur les clés policy.
                            </TextBlock>

                            <StackPanel Orientation="Horizontal" Grid.Column="1" HorizontalAlignment="Right">
                                <Button x:Name="BtnRefreshTweaks" Content="Rafraîchir" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnLoadRecommended" Content="Charger recommandés" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnApplySelected" Content="Appliquer sélection" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnApplyAll" Content="Appliquer tout (Desired)" Margin="4" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <DataGrid x:Name="GridSettings" Grid.Row="2"
                              AutoGenerateColumns="False"
                              CanUserAddRows="False"
                              IsReadOnly="False"
                              SelectionMode="Single"
                              SelectionUnit="FullRow"
                              GridLinesVisibility="Horizontal"
                              HeadersVisibility="Column"
                              RowHeight="30">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Catégorie" Binding="{Binding Category}" Width="170" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Paramètre" Binding="{Binding Name}" Width="280" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Valeur" Binding="{Binding ValueName}" Width="190" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Actuel" Binding="{Binding Current}" Width="95" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Recommandé" Binding="{Binding Recommended}" Width="115" IsReadOnly="True"/>

                            <DataGridComboBoxColumn Header="Desired"
                                                    Width="120"
                                                    SelectedItemBinding="{Binding Desired, UpdateSourceTrigger=PropertyChanged}">
                                <DataGridComboBoxColumn.EditingElementStyle>
                                    <Style TargetType="ComboBox">
                                        <Setter Property="ItemsSource">
                                            <Setter.Value>
                                                <x:Array Type="{x:Type sys:String}" xmlns:sys="clr-namespace:System;assembly=mscorlib">
                                                    <sys:String></sys:String>
                                                    <sys:String>0</sys:String>
                                                    <sys:String>1</sys:String>
                                                    <sys:String>(Remove)</sys:String>
                                                </x:Array>
                                            </Setter.Value>
                                        </Setter>
                                    </Style>
                                </DataGridComboBoxColumn.EditingElementStyle>
                            </DataGridComboBoxColumn>

                            <DataGridTextColumn Header="Chemin registre" Binding="{Binding KeyPath}" Width="310" IsReadOnly="True"/>
                            <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*" IsReadOnly="True"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <TabItem Header="Bases (EDB)">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="0" Margin="0,0,0,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <StackPanel Orientation="Vertical">
                                <TextBlock x:Name="TxtWSearchStatus" Opacity="0.9"/>
                                <TextBlock x:Name="TxtPerUserTotalSize" Opacity="0.9" Margin="0,4,0,0"/>
                                <TextBlock Opacity="0.85" TextWrapping="Wrap">
                                    Actions: Scan = liste les bases globales et per-user. Supprimer une base forcera une reconstruction.
                                    Recommandé: Stop WSearch avant suppression globale (Windows.edb).
                                </TextBlock>
                            </StackPanel>

                            <StackPanel Orientation="Horizontal" Grid.Column="1" HorizontalAlignment="Right">
                                <Button x:Name="BtnScanDb" Content="Scanner" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnOpenDbFolder" Content="Ouvrir dossier" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnStopWSearch" Content="Stop WSearch" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnStartWSearch" Content="Start WSearch" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnRestartWSearchDb" Content="Restart WSearch" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnDeleteDb" Content="Supprimer base sélectionnée" Margin="4" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <DataGrid x:Name="GridDb" Grid.Row="1"
                              AutoGenerateColumns="False"
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              SelectionMode="Single"
                              SelectionUnit="FullRow"
                              GridLinesVisibility="Horizontal"
                              HeadersVisibility="Column"
                              RowHeight="30">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="90"/>
                            <DataGridTextColumn Header="User" Binding="{Binding User}" Width="240"/>
                            <DataGridTextColumn Header="SID" Binding="{Binding SID}" Width="230"/>
                            <DataGridTextColumn Header="Size (MB)" Binding="{Binding SizeMB}" Width="95"/>
                            <DataGridTextColumn Header="LastWrite" Binding="{Binding LastWrite}" Width="165"/>
                            <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <TabItem Header="Logs">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="0" Margin="0,0,0,8">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <StackPanel Orientation="Horizontal" Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock VerticalAlignment="Center" Margin="0,0,8,0">Filtres niveau:</TextBlock>
                                <CheckBox x:Name="ChkError" Content="Erreurs" IsChecked="True" Margin="4,0"/>
                                <CheckBox x:Name="ChkWarning" Content="Avertissements" IsChecked="True" Margin="4,0"/>
                                <CheckBox x:Name="ChkInfo" Content="Information" IsChecked="True" Margin="4,0"/>

                                <TextBlock VerticalAlignment="Center" Margin="20,0,8,0">Max events:</TextBlock>
                                <ComboBox x:Name="CmbMaxEvents" Width="80" SelectedIndex="1">
                                    <ComboBoxItem Content="50"/>
                                    <ComboBoxItem Content="100"/>
                                    <ComboBoxItem Content="200"/>
                                    <ComboBoxItem Content="500"/>
                                </ComboBox>

                                <TextBlock VerticalAlignment="Center" Margin="20,0,8,0">Recherche:</TextBlock>
                                <TextBox x:Name="TxtLogFilter" Width="180" Margin="4,0"/>
                            </StackPanel>

                            <StackPanel Orientation="Horizontal" Grid.Row="1" HorizontalAlignment="Right">
                                <Button x:Name="BtnRefreshLogs" Content="Charger les logs" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnClearLogFilter" Content="Effacer filtre" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnExportLogs" Content="Exporter CSV" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnOpenEventViewer" Content="Event Viewer" Margin="4" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <DataGrid x:Name="GridLogs" Grid.Row="1"
                              AutoGenerateColumns="False"
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              SelectionMode="Single"
                              SelectionUnit="FullRow"
                              GridLinesVisibility="Horizontal"
                              HeadersVisibility="Column"
                              RowHeight="28">
                        <DataGrid.RowStyle>
                            <Style TargetType="DataGridRow">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding Level}" Value="Error">
                                        <Setter Property="Background" Value="#4CFF4444"/>
                                        <Setter Property="Foreground" Value="White"/>
                                    </DataTrigger>
                                    <DataTrigger Binding="{Binding Level}" Value="Critical">
                                        <Setter Property="Background" Value="#66FF0000"/>
                                        <Setter Property="Foreground" Value="White"/>
                                    </DataTrigger>
                                    <DataTrigger Binding="{Binding Level}" Value="Warning">
                                        <Setter Property="Background" Value="#4CFFA500"/>
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </DataGrid.RowStyle>
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Date/Heure" Binding="{Binding TimeCreated, StringFormat='{}{0:dd/MM/yyyy HH:mm:ss}'}" Width="150"/>
                            <DataGridTextColumn Header="Niveau" Binding="{Binding Level}" Width="90">
                                <DataGridTextColumn.ElementStyle>
                                    <Style TargetType="TextBlock">
                                        <Style.Triggers>
                                            <Trigger Property="Text" Value="Error">
                                                <Setter Property="Foreground" Value="#FF4444"/>
                                                <Setter Property="FontWeight" Value="SemiBold"/>
                                            </Trigger>
                                            <Trigger Property="Text" Value="Critical">
                                                <Setter Property="Foreground" Value="#FF0000"/>
                                                <Setter Property="FontWeight" Value="Bold"/>
                                            </Trigger>
                                            <Trigger Property="Text" Value="Warning">
                                                <Setter Property="Foreground" Value="#FFA500"/>
                                            </Trigger>
                                        </Style.Triggers>
                                    </Style>
                                </DataGridTextColumn.ElementStyle>
                            </DataGridTextColumn>
                            <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="60"/>
                            <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="200"/>
                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="2" Margin="0,8,0,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" FontWeight="SemiBold" Margin="0,0,0,4">Détail du message sélectionné:</TextBlock>
                            <TextBox x:Name="TxtLogDetail" Grid.Row="1"
                                     IsReadOnly="True"
                                     TextWrapping="Wrap"
                                     VerticalScrollBarVisibility="Auto"
                                     Height="180"
                                     Background="#1E1E1E"
                                     Foreground="#CCCCCC"
                                     Padding="8"/>
                        </Grid>
                    </Border>
                </Grid>
            </TabItem>

            <TabItem Header="Index Status">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="12" Grid.Row="0" Margin="0,0,0,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <StackPanel Orientation="Vertical">
                                <TextBlock FontWeight="SemiBold" FontSize="14" Margin="0,0,0,8">Statut de l'indexation Windows Search</TextBlock>
                                <Grid>
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="200"/>
                                        <ColumnDefinition Width="200"/>
                                        <ColumnDefinition Width="200"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>

                                    <TextBlock Grid.Row="0" Grid.Column="0" Margin="0,2">Service WSearch:</TextBlock>
                                    <TextBlock Grid.Row="0" Grid.Column="1" x:Name="TxtIdxServiceStatus" FontWeight="SemiBold" Margin="0,2">-</TextBlock>

                                    <TextBlock Grid.Row="0" Grid.Column="2" Margin="0,2">Type démarrage:</TextBlock>
                                    <TextBlock Grid.Row="0" Grid.Column="3" x:Name="TxtIdxStartType" FontWeight="SemiBold" Margin="0,2">-</TextBlock>

                                    <TextBlock Grid.Row="1" Grid.Column="0" Margin="0,2">Statut catalogue:</TextBlock>
                                    <TextBlock Grid.Row="1" Grid.Column="1" x:Name="TxtIdxCatalogStatus" FontWeight="SemiBold" Margin="0,2">-</TextBlock>

                                    <TextBlock Grid.Row="1" Grid.Column="2" Margin="0,2">Éléments indexés:</TextBlock>
                                    <TextBlock Grid.Row="1" Grid.Column="3" x:Name="TxtIdxItemsCount" FontWeight="SemiBold" Margin="0,2">-</TextBlock>

                                    <TextBlock Grid.Row="2" Grid.Column="0" Margin="0,2">Taille index (MB):</TextBlock>
                                    <TextBlock Grid.Row="2" Grid.Column="1" x:Name="TxtIdxSizeMB" FontWeight="SemiBold" Margin="0,2">-</TextBlock>

                                    <TextBlock Grid.Row="2" Grid.Column="2" Margin="0,2">Dernière MAJ:</TextBlock>
                                    <TextBlock Grid.Row="2" Grid.Column="3" x:Name="TxtIdxLastUpdate" FontWeight="SemiBold" Margin="0,2">-</TextBlock>
                                </Grid>
                            </StackPanel>

                            <StackPanel Orientation="Horizontal" Grid.Column="1" VerticalAlignment="Top">
                                <Button x:Name="BtnRefreshIndexStatus" Content="Rafraîchir statut" Margin="4" Padding="12,6"/>
                                <Button x:Name="BtnOpenIndexOptions" Content="Options d'indexation" Margin="4" Padding="12,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="1" Margin="0,0,0,8">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,20,0">Emplacements indexés:</TextBlock>
                            <Button x:Name="BtnRefreshLocations" Content="Charger emplacements" Margin="4" Padding="12,6"/>
                        </StackPanel>
                    </Border>

                    <DataGrid x:Name="GridIndexLocations" Grid.Row="2"
                              AutoGenerateColumns="False"
                              CanUserAddRows="False"
                              IsReadOnly="True"
                              SelectionMode="Single"
                              SelectionUnit="FullRow"
                              GridLinesVisibility="Horizontal"
                              HeadersVisibility="Column"
                              RowHeight="28">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="100"/>
                            <DataGridTextColumn Header="Chemin / URL" Binding="{Binding Path}" Width="*"/>
                            <DataGridTextColumn Header="Inclus" Binding="{Binding Included}" Width="80">
                                <DataGridTextColumn.ElementStyle>
                                    <Style TargetType="TextBlock">
                                        <Style.Triggers>
                                            <Trigger Property="Text" Value="Oui">
                                                <Setter Property="Foreground" Value="#44FF44"/>
                                            </Trigger>
                                            <Trigger Property="Text" Value="Non">
                                                <Setter Property="Foreground" Value="#FF4444"/>
                                            </Trigger>
                                        </Style.Triggers>
                                    </Style>
                                </DataGridTextColumn.ElementStyle>
                            </DataGridTextColumn>
                            <DataGridTextColumn Header="Source" Binding="{Binding Status}" Width="100"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <TabItem Header="Maintenance">
                <Grid Margin="8">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="12" Grid.Row="0" Margin="0,0,0,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>

                            <StackPanel Orientation="Vertical">
                                <TextBlock FontWeight="SemiBold" FontSize="14" Margin="0,0,0,8">Actions de maintenance et réparation</TextBlock>
                                <TextBlock TextWrapping="Wrap" Opacity="0.85">
                                    Utilisez ces outils pour diagnostiquer et réparer les problèmes courants de Windows Search.
                                    ATTENTION: Certaines actions peuvent nécessiter une reconstruction complète de l'index (plusieurs heures).
                                </TextBlock>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" Grid.Column="1" VerticalAlignment="Top">
                                <Button x:Name="BtnRunDiagnostics" Content="Lancer le diagnostic" Margin="4" Padding="12,6" FontWeight="SemiBold"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="12" Grid.Row="1" Margin="0,0,0,8">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="1.3*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <StackPanel Grid.Column="0" Margin="4">
                                <TextBlock FontWeight="SemiBold" Margin="0,0,0,4">Index Global</TextBlock>
                                <Button x:Name="BtnRebuildIndex" Content="Reconstruire l'index" Margin="0,2" Padding="8,6"
                                        ToolTip="Supprime Windows.edb et force une reconstruction complète de l'index (peut prendre plusieurs heures)"/>
                                <Button x:Name="BtnRepairService" Content="Réparer le service" Margin="0,2" Padding="8,6"
                                        ToolTip="Réinitialise la configuration du service et ré-enregistre les composants"/>
                            </StackPanel>

                            <StackPanel Grid.Column="1" Margin="4">
                                <TextBlock FontWeight="SemiBold" Margin="0,0,0,4">Catalogues Per-User</TextBlock>
                                <TextBlock FontSize="10" Opacity="0.7" Margin="0,0,0,4" TextWrapping="Wrap">FSLogix: déconnecter les utilisateurs ou cocher l'option ci-dessous</TextBlock>
                                <CheckBox x:Name="ChkStopWSearchBeforeDelete" Content="Arrêter WSearch avant" Margin="0,2" IsChecked="True"
                                          ToolTip="Arrête le service WSearch avant la suppression pour débloquer les fichiers verrouillés"/>
                                <Button x:Name="BtnDeleteAllPerUser" Content="Supprimer tous" Margin="0,2" Padding="8,6"
                                        ToolTip="Supprime tous les catalogues per-user. Le service WSearch sera arrêté si l'option est cochée."/>
                                <Button x:Name="BtnDeleteSelectedPerUser" Content="Supprimer sélectionné" Margin="0,2" Padding="8,6"
                                        ToolTip="Supprime le catalogue sélectionné dans le diagnostic (ligne PUC)"/>
                                <Button x:Name="BtnShowConnectedUsers" Content="Utilisateurs connectés" Margin="0,2" Padding="8,6"
                                        ToolTip="Affiche la liste des utilisateurs actuellement connectés"/>
                            </StackPanel>

                            <StackPanel Grid.Column="2" Margin="4">
                                <TextBlock FontWeight="SemiBold" Margin="0,0,0,4">Journal USN (Update Sequence Number)</TextBlock>
                                <TextBlock FontSize="10" Opacity="0.7" Margin="0,0,0,4" TextWrapping="Wrap">Journal NTFS qui enregistre les modifications de fichiers. Windows Search l'utilise pour détecter les fichiers modifiés. Erreur 3079 = quota insuffisant.</TextBlock>
                                <Button x:Name="BtnResetUSN" Content="Réinitialiser USN (C:)" Margin="0,2" Padding="8,6"
                                        ToolTip="Supprime et recrée le journal USN sur C:. Corrige l'erreur 3079. Redémarrer WSearch après."/>
                            </StackPanel>

                            <StackPanel Grid.Column="3" Margin="4">
                                <TextBlock FontWeight="SemiBold" Margin="0,0,0,4">Service WSearch</TextBlock>
                                <Button x:Name="BtnStopWSearchMaint" Content="Arrêter" Margin="0,2" Padding="8,6"/>
                                <Button x:Name="BtnStartWSearchMaint" Content="Démarrer" Margin="0,2" Padding="8,6"/>
                                <Button x:Name="BtnRestartWSearchMaint" Content="Redémarrer" Margin="0,2" Padding="8,6"/>
                            </StackPanel>
                        </Grid>
                    </Border>

                    <Grid Grid.Row="2">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <TextBlock Grid.Row="0" FontWeight="SemiBold" Margin="0,0,0,8">Résultats du diagnostic (erreurs des 7 derniers jours):</TextBlock>

                        <DataGrid x:Name="GridDiagnostics" Grid.Row="1"
                                  AutoGenerateColumns="False"
                                  CanUserAddRows="False"
                                  IsReadOnly="True"
                                  SelectionMode="Single"
                                  SelectionUnit="FullRow"
                                  GridLinesVisibility="Horizontal"
                                  HeadersVisibility="Column"
                                  RowHeight="28">
                            <DataGrid.RowStyle>
                                <Style TargetType="DataGridRow">
                                    <Style.Triggers>
                                        <DataTrigger Binding="{Binding Severity}" Value="Critical">
                                            <Setter Property="Background" Value="#66FF0000"/>
                                            <Setter Property="Foreground" Value="White"/>
                                        </DataTrigger>
                                        <DataTrigger Binding="{Binding Severity}" Value="Error">
                                            <Setter Property="Background" Value="#4CFF4444"/>
                                            <Setter Property="Foreground" Value="White"/>
                                        </DataTrigger>
                                        <DataTrigger Binding="{Binding Severity}" Value="Warning">
                                            <Setter Property="Background" Value="#4CFFA500"/>
                                        </DataTrigger>
                                    </Style.Triggers>
                                </Style>
                            </DataGrid.RowStyle>
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Event ID" Binding="{Binding EventId}" Width="80"/>
                                <DataGridTextColumn Header="Nb" Binding="{Binding Count}" Width="50"/>
                                <DataGridTextColumn Header="Sévérité" Binding="{Binding Severity}" Width="80"/>
                                <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="200"/>
                                <DataGridTextColumn Header="Solution recommandée" Binding="{Binding Solution}" Width="250"/>
                                <DataGridTextColumn Header="Dernière occurrence" Binding="{Binding LastOccurrence, StringFormat='{}{0:dd/MM/yyyy HH:mm}'}" Width="140"/>
                                <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </Grid>
                </Grid>
            </TabItem>
        </TabControl>

        <Border Grid.Row="2" BorderBrush="#444" BorderThickness="1" CornerRadius="6" Padding="10" Margin="0,10,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock x:Name="TxtStatus" VerticalAlignment="Center" Opacity="0.9">Prêt.</TextBlock>
                <TextBlock Grid.Column="1" x:Name="TxtHint" VerticalAlignment="Center" Opacity="0.8"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader($Xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$GridSettings         = $window.FindName("GridSettings")
$GridDb               = $window.FindName("GridDb")
$TxtStatus            = $window.FindName("TxtStatus")
$TxtHint              = $window.FindName("TxtHint")
$TxtSystemInfo        = $window.FindName("TxtSystemInfo")

# Top buttons
$BtnBackup            = $window.FindName("BtnBackup")
$BtnRestartWSearchTop = $window.FindName("BtnRestartWSearchTop")
$BtnOpenServices      = $window.FindName("BtnOpenServices")

# Tweaks tab buttons
$BtnRefreshTweaks     = $window.FindName("BtnRefreshTweaks")
$BtnLoadRecommended   = $window.FindName("BtnLoadRecommended")
$BtnApplySelected     = $window.FindName("BtnApplySelected")
$BtnApplyAll          = $window.FindName("BtnApplyAll")

# DB tab controls
$TxtWSearchStatus     = $window.FindName("TxtWSearchStatus")
$TxtPerUserTotalSize  = $window.FindName("TxtPerUserTotalSize")
$BtnScanDb            = $window.FindName("BtnScanDb")
$BtnOpenDbFolder      = $window.FindName("BtnOpenDbFolder")
$BtnStopWSearch       = $window.FindName("BtnStopWSearch")
$BtnStartWSearch      = $window.FindName("BtnStartWSearch")
$BtnRestartWSearchDb  = $window.FindName("BtnRestartWSearchDb")
$BtnDeleteDb          = $window.FindName("BtnDeleteDb")

# Logs tab controls
$GridLogs             = $window.FindName("GridLogs")
$TxtLogDetail         = $window.FindName("TxtLogDetail")
$TxtLogFilter         = $window.FindName("TxtLogFilter")
$ChkError             = $window.FindName("ChkError")
$ChkWarning           = $window.FindName("ChkWarning")
$ChkInfo              = $window.FindName("ChkInfo")
$CmbMaxEvents         = $window.FindName("CmbMaxEvents")
$BtnRefreshLogs       = $window.FindName("BtnRefreshLogs")
$BtnClearLogFilter    = $window.FindName("BtnClearLogFilter")
$BtnExportLogs        = $window.FindName("BtnExportLogs")
$BtnOpenEventViewer   = $window.FindName("BtnOpenEventViewer")

# Index Status tab controls
$TxtIdxServiceStatus  = $window.FindName("TxtIdxServiceStatus")
$TxtIdxStartType      = $window.FindName("TxtIdxStartType")
$TxtIdxCatalogStatus  = $window.FindName("TxtIdxCatalogStatus")
$TxtIdxItemsCount     = $window.FindName("TxtIdxItemsCount")
$TxtIdxSizeMB         = $window.FindName("TxtIdxSizeMB")
$TxtIdxLastUpdate     = $window.FindName("TxtIdxLastUpdate")
$GridIndexLocations   = $window.FindName("GridIndexLocations")
$BtnRefreshIndexStatus = $window.FindName("BtnRefreshIndexStatus")
$BtnOpenIndexOptions  = $window.FindName("BtnOpenIndexOptions")
$BtnRefreshLocations  = $window.FindName("BtnRefreshLocations")

# Maintenance tab controls
$GridDiagnostics      = $window.FindName("GridDiagnostics")
$BtnRunDiagnostics    = $window.FindName("BtnRunDiagnostics")
$BtnRebuildIndex      = $window.FindName("BtnRebuildIndex")
$BtnRepairService     = $window.FindName("BtnRepairService")
$BtnDeleteAllPerUser  = $window.FindName("BtnDeleteAllPerUser")
$BtnDeleteSelectedPerUser = $window.FindName("BtnDeleteSelectedPerUser")
$BtnResetUSN          = $window.FindName("BtnResetUSN")
$BtnStopWSearchMaint  = $window.FindName("BtnStopWSearchMaint")
$BtnStartWSearchMaint = $window.FindName("BtnStartWSearchMaint")
$BtnRestartWSearchMaint = $window.FindName("BtnRestartWSearchMaint")
$ChkStopWSearchBeforeDelete = $window.FindName("ChkStopWSearchBeforeDelete")
$BtnShowConnectedUsers = $window.FindName("BtnShowConnectedUsers")

# Profile selector controls (Tweaks tab)
$CmbProfileType       = $window.FindName("CmbProfileType")
$TxtDetectedProfile   = $window.FindName("TxtDetectedProfile")
$TxtProfileDescription = $window.FindName("TxtProfileDescription")
$TxtProfileNotes      = $window.FindName("TxtProfileNotes")

function Set-Status([string]$msg) { $TxtStatus.Text = $msg }

function Build-SystemInfoText {
    $fs = if ($script:hasFSLogix) { "FSLogix: Oui" } else { "FSLogix: Non" }
    $upd = if ($script:hasUPD) { "UPD: Oui" } else { "UPD: Non" }
    $roaming = if ($script:hasRoamingProfiles) { "Roaming: Oui" } else { "Roaming: Non" }
    $type = if ($script:isServer) { "Type: Server" } else { "Type: Workstation" }
    $modern = if ($script:isModernBuild) { "Build moderne: Oui (>= 17763)" } else { "Build moderne: Non (< 17763)" }
    return "$($script:osCaption) | Version $($script:osVersion) (Build $($script:osBuild)) | $type | $modern | $fs | $upd | $roaming"
}

function Update-ProfileSelector {
    # Update detected profile indicator
    $TxtDetectedProfile.Text = "(Détecté: $($script:detectedProfileType))"

    # Select the appropriate ComboBox item based on selected profile type
    $profileMapping = @{
        "Local" = 0
        "FSLogix" = 1
        "UPD" = 2
        "Roaming" = 3
    }

    $index = $profileMapping[$script:selectedProfileType]
    if ($null -ne $index) {
        $CmbProfileType.SelectedIndex = $index
    }

    # Update description and notes
    $recs = $ProfileRecommendations[$script:selectedProfileType]
    if ($recs) {
        $TxtProfileDescription.Text = $recs.Description
        $TxtProfileNotes.Text = $recs.Notes
    }
}

function Set-ProfileType([string]$profileType) {
    $script:selectedProfileType = $profileType

    # Update description and notes
    $recs = $ProfileRecommendations[$profileType]
    if ($recs) {
        $TxtProfileDescription.Text = $recs.Description
        $TxtProfileNotes.Text = $recs.Notes
    }

    # Refresh the settings grid to show updated recommendations
    Refresh-Tweaks
}

# Bind data
$UiRows = Build-UiRows
$GridSettings.ItemsSource = $UiRows
$TxtSystemInfo.Text = Build-SystemInfoText
$TxtWSearchStatus.Text = Get-WSearchStatusText

# DB datasource
$DbRows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$GridDb.ItemsSource = $DbRows

# Logs datasource
$LogRows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$GridLogs.ItemsSource = $LogRows

# Index locations datasource
$IndexLocationRows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$GridIndexLocations.ItemsSource = $IndexLocationRows

# Diagnostics datasource
$DiagnosticsRows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$GridDiagnostics.ItemsSource = $DiagnosticsRows

function Refresh-Tweaks {
    $global:UiRows = Build-UiRows
    $GridSettings.ItemsSource = $global:UiRows
    $TxtSystemInfo.Text = Build-SystemInfoText
    Set-Status "Tweaks rafraîchis."
}

function Apply-Row($row) {
    if ($null -eq $row) { return }
    $desired = $row.Desired
    if ([string]::IsNullOrWhiteSpace($desired)) {
        throw "Aucune valeur Desired définie pour '$($row.Name)'."
    }

    if ($desired -eq "(Remove)") {
        Remove-RegValue -Path $row.KeyPath -Name $row.ValueName
        return
    }

    if ($desired -notin @("0","1")) {
        throw "Desired invalide: '$desired' (attendu: 0, 1 ou (Remove))."
    }
    Set-RegDword -Path $row.KeyPath -Name $row.ValueName -Value ([int]$desired)
}

function Apply-AllDesired {
    $applied = 0
    foreach ($r in $UiRows) {
        if (-not [string]::IsNullOrWhiteSpace($r.Desired)) {
            Apply-Row $r
            $applied++
        }
    }
    return $applied
}

function Load-Recommended {
    foreach ($r in $UiRows) {
        if (-not [string]::IsNullOrWhiteSpace($r.Recommended)) {
            $r.Desired = $r.Recommended
        }
    }
}

function Scan-DbToGrid {
    $TxtWSearchStatus.Text = Get-WSearchStatusText
    $items = Scan-SearchDatabases
    $DbRows.Clear()
    foreach ($i in $items) { $DbRows.Add($i) }

    # Calculate per-user total size
    $perUserItems = $items | Where-Object { $_.Scope -eq "Per-user" }
    $perUserCount = ($perUserItems | Measure-Object).Count
    $perUserTotalMB = ($perUserItems | ForEach-Object {
        $sizeTxt = $_.SizeMB -replace "[^\d\.]", ""
        if ($sizeTxt) { [double]$sizeTxt } else { 0 }
    } | Measure-Object -Sum).Sum

    # Calculate global size
    $globalItem = $items | Where-Object { $_.Scope -eq "Global" } | Select-Object -First 1
    $globalSizeMB = 0
    if ($globalItem) {
        $sizeTxt = $globalItem.SizeMB -replace "[^\d\.]", ""
        if ($sizeTxt) { $globalSizeMB = [double]$sizeTxt }
    }

    $TxtPerUserTotalSize.Text = "Index per-user: $perUserCount base(s), Total: $([math]::Round($perUserTotalMB, 2)) MB | Index global: $([math]::Round($globalSizeMB, 2)) MB | Total général: $([math]::Round($perUserTotalMB + $globalSizeMB, 2)) MB"

    Set-Status "Scan terminé: $($items.Count) entrée(s)."
}

# -------------------------
# Events - Top
# -------------------------
$BtnOpenServices.Add_Click({
    try { Start-Process "services.msc" | Out-Null } catch { }
})

$BtnRestartWSearchTop.Add_Click({
    try {
        Restart-WSearch
        $TxtWSearchStatus.Text = Get-WSearchStatusText
        Set-Status "WSearch redémarré."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnBackup.Add_Click({
    try {
        $dir = "C:\Temp"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $ts  = Get-Date -Format "yyyyMMdd_HHmmss"

        $file1 = Join-Path $dir "WindowsSearch_Policies_$ts.reg"
        $file2 = Join-Path $dir "WindowsSearch_Base_$ts.reg"

        Backup-RegistryKeyToRegFile -RegKey "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -OutFile $file1
        Backup-RegistryKeyToRegFile -RegKey "HKLM\SOFTWARE\Microsoft\Windows Search" -OutFile $file2

        if ($script:hasFSLogix) {
            $file3 = Join-Path $dir "FSLogix_$ts.reg"
            Backup-RegistryKeyToRegFile -RegKey "HKLM\SOFTWARE\FSLogix" -OutFile $file3
        }

        Set-Status "Backup créé dans $dir"
        [System.Windows.MessageBox]::Show("Backup OK dans $dir", "Backup", "OK", "Information") | Out-Null
    } catch {
        Set-Status "Erreur backup: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

# -------------------------
# Events - Tweaks tab
# -------------------------

# Profile type selector
$CmbProfileType.Add_SelectionChanged({
    $selectedItem = $CmbProfileType.SelectedItem
    if ($selectedItem) {
        $tag = $selectedItem.Tag
        if ($tag -and $tag -ne $script:selectedProfileType) {
            Set-ProfileType $tag
        }
    }
})

$BtnRefreshTweaks.Add_Click({
    try { Refresh-Tweaks } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnLoadRecommended.Add_Click({
    try {
        Load-Recommended
        Set-Status "Recommandés chargés dans Desired."
        $TxtHint.Text = "Clique 'Appliquer tout (Desired)'"
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
    }
})

$BtnApplySelected.Add_Click({
    try {
        $row = $GridSettings.SelectedItem
        if ($null -eq $row) { throw "Sélectionne une ligne." }
        Apply-Row $row
        Refresh-Tweaks
        Set-Status "Appliqué: $($row.Name)"
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnApplyAll.Add_Click({
    try {
        $count = Apply-AllDesired
        Refresh-Tweaks
        Set-Status "Appliqué: $count paramètre(s)."
        $TxtHint.Text = ""
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

# -------------------------
# Events - DB tab
# -------------------------
$BtnScanDb.Add_Click({
    try { Scan-DbToGrid } catch {
        Set-Status "Erreur scan: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnOpenDbFolder.Add_Click({
    try {
        $row = $GridDb.SelectedItem
        if ($null -eq $row) { throw "Sélectionne une base." }
        if ($row.Path -like "(Introuvable)*") { throw "Chemin introuvable." }

        $folder = Split-Path $row.Path -Parent
        if (Test-Path $folder) { Start-Process "explorer.exe" $folder | Out-Null }
        Set-Status "Dossier ouvert: $folder"
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnStopWSearch.Add_Click({
    try {
        Stop-WSearch
        $TxtWSearchStatus.Text = Get-WSearchStatusText
        Set-Status "WSearch stoppé."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnStartWSearch.Add_Click({
    try {
        Start-WSearch
        $TxtWSearchStatus.Text = Get-WSearchStatusText
        Set-Status "WSearch démarré."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnRestartWSearchDb.Add_Click({
    try {
        Restart-WSearch
        $TxtWSearchStatus.Text = Get-WSearchStatusText
        Set-Status "WSearch redémarré."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnDeleteDb.Add_Click({
    try {
        $row = $GridDb.SelectedItem
        if ($null -eq $row) { throw "Sélectionne une base." }
        if ($row.Path -like "(Introuvable)*") { throw "Chemin introuvable." }

        $warning = @"
Tu es sur le point de supprimer une base Windows Search:

Scope : $($row.Scope)
User  : $($row.User)
Path  : $($row.Path)

Conséquence:
- l'index sera reconstruit automatiquement (au prochain usage/logon)
- possible pic CPU/DISK pendant la reconstruction

Confirmer la suppression ?
"@

        $res = [System.Windows.MessageBox]::Show($warning, "Confirmation", "YesNo", "Warning")
        if ($res -ne "Yes") { return }

        # Recommandation sécurité: si Global, stopper WSearch avant suppression
        if ($row.Scope -eq "Global") {
            $svc = Get-Service WSearch -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                $res2 = [System.Windows.MessageBox]::Show(
                    "WSearch est en cours d'exécution. Recommandé: Stop WSearch avant suppression globale. Stop maintenant ?",
                    "WSearch", "YesNo", "Warning"
                )
                if ($res2 -eq "Yes") { Stop-WSearch }
            }
        }

        Remove-DbFile -path $row.Path
        Set-Status "Base supprimée: $($row.Path)"
        Scan-DbToGrid
    } catch {
        Set-Status "Erreur suppression: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

# -------------------------
# Events - Logs tab
# -------------------------
function Refresh-LogsToGrid {
    $levels = @()
    if ($ChkError.IsChecked)   { $levels += "Error"; $levels += "Critical" }
    if ($ChkWarning.IsChecked) { $levels += "Warning" }
    if ($ChkInfo.IsChecked)    { $levels += "Information" }

    $maxEventsText = ($CmbMaxEvents.SelectedItem).Content
    $maxEvents = [int]$maxEventsText

    $filterText = $TxtLogFilter.Text

    Set-Status "Chargement des logs..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $logs = Get-WindowsSearchLogs -MaxEvents $maxEvents -Levels $levels -FilterText $filterText
        $LogRows.Clear()
        foreach ($l in $logs) { $LogRows.Add($l) }
        Set-Status "Logs chargés: $($logs.Count) entrée(s)."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
    } finally {
        $window.Cursor = $null
    }
}

$BtnRefreshLogs.Add_Click({
    try { Refresh-LogsToGrid } catch {
        Set-Status "Erreur chargement logs: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnClearLogFilter.Add_Click({
    $TxtLogFilter.Text = ""
    Set-Status "Filtre effacé."
})

$BtnExportLogs.Add_Click({
    try {
        if ($LogRows.Count -eq 0) { throw "Aucun log à exporter. Charge d'abord les logs." }

        $dir = "C:\Temp"
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $ts = Get-Date -Format "yyyyMMdd_HHmmss"
        $filePath = Join-Path $dir "WindowsSearch_Logs_$ts.csv"

        Export-LogsToCsv -Logs $LogRows -FilePath $filePath
        Set-Status "Logs exportés: $filePath"
        [System.Windows.MessageBox]::Show("Logs exportés vers:`n$filePath", "Export", "OK", "Information") | Out-Null
    } catch {
        Set-Status "Erreur export: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnOpenEventViewer.Add_Click({
    try {
        Open-EventViewer-SearchLogs
        Set-Status "Event Viewer ouvert."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
    }
})

# Event: Show detail when selecting a log row
$GridLogs.Add_SelectionChanged({
    $row = $GridLogs.SelectedItem
    if ($null -ne $row) {
        $TxtLogDetail.Text = $row.FullMessage
    } else {
        $TxtLogDetail.Text = ""
    }
})

# -------------------------
# Events - Index Status tab
# -------------------------
function Refresh-IndexStatusUI {
    Set-Status "Chargement du statut d'indexation..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $status = Get-SearchIndexStatus

        $TxtIdxServiceStatus.Text = $status.ServiceStatus
        $TxtIdxStartType.Text = $status.ServiceStartType
        $TxtIdxCatalogStatus.Text = $status.CatalogStatus
        $TxtIdxItemsCount.Text = "{0:N0}" -f $status.ItemsIndexed
        $TxtIdxSizeMB.Text = "{0:N2} MB" -f $status.IndexSizeMB

        if ($status.LastIndexTime) {
            $TxtIdxLastUpdate.Text = $status.LastIndexTime.ToString("dd/MM/yyyy HH:mm:ss")
        } else {
            $TxtIdxLastUpdate.Text = "-"
        }

        # Color code service status
        if ($status.ServiceStatus -eq "Running") {
            $TxtIdxServiceStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
        } elseif ($status.ServiceStatus -eq "Stopped") {
            $TxtIdxServiceStatus.Foreground = [System.Windows.Media.Brushes]::OrangeRed
        } else {
            $TxtIdxServiceStatus.Foreground = [System.Windows.Media.Brushes]::White
        }

        Set-Status "Statut d'indexation chargé."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
    } finally {
        $window.Cursor = $null
    }
}

function Refresh-IndexLocationsUI {
    Set-Status "Chargement des emplacements indexés..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $locations = Get-IndexedLocations
        $IndexLocationRows.Clear()
        foreach ($loc in $locations) { $IndexLocationRows.Add($loc) }
        Set-Status "Emplacements chargés: $($locations.Count) entrée(s)."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
    } finally {
        $window.Cursor = $null
    }
}

$BtnRefreshIndexStatus.Add_Click({
    try { Refresh-IndexStatusUI } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnRefreshLocations.Add_Click({
    try { Refresh-IndexLocationsUI } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnOpenIndexOptions.Add_Click({
    try {
        # Open Windows Indexing Options control panel
        Start-Process "control.exe" -ArgumentList "/name Microsoft.IndexingOptions" -ErrorAction SilentlyContinue
        Set-Status "Options d'indexation ouvertes."
    } catch {
        # Fallback
        try {
            Start-Process "rundll32.exe" -ArgumentList "shell32.dll,Control_RunDLL srchadmin.dll" -ErrorAction SilentlyContinue
            Set-Status "Options d'indexation ouvertes."
        } catch {
            Set-Status "Erreur: $($_.Exception.Message)"
        }
    }
})

# -------------------------
# Events - Maintenance tab
# -------------------------
$BtnRunDiagnostics.Add_Click({
    Set-Status "Exécution du diagnostic..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $diagnostics = Get-SearchDiagnostics
        $DiagnosticsRows.Clear()
        foreach ($d in $diagnostics) { $DiagnosticsRows.Add($d) }

        if ($diagnostics.Count -eq 0) {
            Set-Status "Diagnostic terminé: aucune erreur détectée."
        } else {
            Set-Status "Diagnostic terminé: $($diagnostics.Count) problème(s) détecté(s)."
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnRebuildIndex.Add_Click({
    $warning = @"
ATTENTION: Cette action va supprimer l'index Windows Search global.

Conséquences:
- L'index sera entièrement reconstruit (peut prendre plusieurs heures)
- La recherche Windows sera indisponible pendant la reconstruction
- Pic d'utilisation CPU/Disque pendant la reconstruction

Voulez-vous continuer ?
"@

    $res = [System.Windows.MessageBox]::Show($warning, "Reconstruire l'index", "YesNo", "Warning")
    if ($res -ne "Yes") { return }

    Set-Status "Reconstruction de l'index en cours..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $result = Invoke-RebuildSearchIndex -Force
        if ($result.Success) {
            Set-Status $result.Message
            [System.Windows.MessageBox]::Show($result.Message, "Succès", "OK", "Information") | Out-Null
        } else {
            Set-Status "Erreur: $($result.Message)"
            [System.Windows.MessageBox]::Show($result.Message, "Erreur", "OK", "Error") | Out-Null
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnRepairService.Add_Click({
    Set-Status "Réparation du service WSearch..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $result = Repair-SearchService
        if ($result.Success) {
            Set-Status $result.Message
            [System.Windows.MessageBox]::Show("Étapes effectuées:`n$($result.Steps -join "`n")`n`n$($result.Message)", "Réparation", "OK", "Information") | Out-Null
        } else {
            Set-Status "Erreur: $($result.Message)"
            [System.Windows.MessageBox]::Show($result.Message, "Erreur", "OK", "Error") | Out-Null
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnDeleteAllPerUser.Add_Click({
    $stopService = $ChkStopWSearchBeforeDelete.IsChecked

    $serviceNote = if ($stopService) { "`n- Le service WSearch sera arrêté puis redémarré automatiquement" } else { "" }

    $warning = @"
ATTENTION: Cette action va supprimer TOUS les catalogues Windows Search per-user.

Conséquences:
- Les index per-user seront recréés à la prochaine connexion de chaque utilisateur
- Peut résoudre les erreurs de catalogue corrompu (EventID 7040, 3031)$serviceNote

NOTE FSLogix: Si des utilisateurs sont connectés avec des profils FSLogix,
leurs catalogues ne pourront être supprimés que si le service WSearch est arrêté.

Voulez-vous continuer ?
"@

    $res = [System.Windows.MessageBox]::Show($warning, "Supprimer tous les catalogues per-user", "YesNo", "Warning")
    if ($res -ne "Yes") { return }

    Set-Status "Suppression des catalogues per-user..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        if ($stopService) {
            $result = Remove-PerUserCatalogs -All -StopServiceFirst
        } else {
            $result = Remove-PerUserCatalogs -All
        }

        if ($result.Success) {
            $msg = $result.Message
            if ($result.FailedFiles.Count -gt 0) {
                $msg += "`n`nFichiers non supprimés (utilisateurs connectés?):`n"
                $msg += ($result.FailedFiles | Select-Object -First 5) -join "`n"
                if ($result.FailedFiles.Count -gt 5) {
                    $msg += "`n... et $($result.FailedFiles.Count - 5) autre(s)"
                }
            }
            Set-Status $result.Message
            [System.Windows.MessageBox]::Show($msg, "Résultat", "OK", "Information") | Out-Null
        } else {
            Set-Status "Erreur: $($result.Message)"
            [System.Windows.MessageBox]::Show($result.Message, "Erreur", "OK", "Error") | Out-Null
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnDeleteSelectedPerUser.Add_Click({
    $row = $GridDiagnostics.SelectedItem
    if ($null -eq $row) {
        [System.Windows.MessageBox]::Show("Sélectionnez d'abord un élément PUC (catalogue per-user) dans la grille de diagnostic.", "Information", "OK", "Information") | Out-Null
        return
    }

    if ($row.EventId -ne "PUC") {
        [System.Windows.MessageBox]::Show("L'élément sélectionné n'est pas un catalogue per-user. Sélectionnez une ligne avec EventId = PUC.", "Information", "OK", "Information") | Out-Null
        return
    }

    # Extract path from solution field
    $path = $row.Solution -replace "Supprimer le catalogue per-user: ", ""

    $stopService = $ChkStopWSearchBeforeDelete.IsChecked
    $serviceNote = if ($stopService) { "`n`nLe service WSearch sera arrêté puis redémarré." } else { "" }

    $res = [System.Windows.MessageBox]::Show("Supprimer le fichier:`n$path$serviceNote`n`nContinuer ?", "Confirmation", "YesNo", "Warning")
    if ($res -ne "Yes") { return }

    Set-Status "Suppression du catalogue..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        if ($stopService) {
            $result = Remove-PerUserCatalogs -SpecificFile $path -StopServiceFirst
        } else {
            $result = Remove-PerUserCatalogs -SpecificFile $path
        }

        if ($result.Success -and $result.DeletedCount -gt 0) {
            Set-Status "Catalogue supprimé: $path"
            [System.Windows.MessageBox]::Show("Catalogue supprimé avec succès.", "Succès", "OK", "Information") | Out-Null
        } elseif ($result.FailedFiles.Count -gt 0) {
            Set-Status "Échec de la suppression"
            [System.Windows.MessageBox]::Show("Impossible de supprimer le fichier. L'utilisateur est probablement connecté.`n`nEssayez de:`n1. Déconnecter l'utilisateur`n2. Ou arrêter manuellement le service WSearch", "Erreur", "OK", "Error") | Out-Null
        } else {
            Set-Status "Fichier non trouvé"
            [System.Windows.MessageBox]::Show("Le fichier n'existe pas ou a déjà été supprimé.", "Information", "OK", "Information") | Out-Null
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnShowConnectedUsers.Add_Click({
    try {
        $users = Get-ConnectedUsers

        if ($users.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Aucun utilisateur connecté détecté.", "Utilisateurs connectés", "OK", "Information") | Out-Null
        } else {
            $msg = "Utilisateurs actuellement connectés:`n`n"
            foreach ($u in $users) {
                $msg += "- $($u.Username) (Session: $($u.SessionName), État: $($u.State))`n"
            }
            $msg += "`nPour supprimer les catalogues per-user de ces utilisateurs:`n"
            $msg += "1. Déconnectez les utilisateurs, OU`n"
            $msg += "2. Cochez 'Arrêter WSearch avant' et utilisez 'Supprimer tous'"

            [System.Windows.MessageBox]::Show($msg, "Utilisateurs connectés", "OK", "Information") | Out-Null
        }
        Set-Status "Utilisateurs connectés: $($users.Count)"
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnResetUSN.Add_Click({
    $warning = @"
ATTENTION: Cette action va réinitialiser le journal USN du volume C:.

Le journal USN (Update Sequence Number) est utilisé par Windows Search pour suivre les modifications de fichiers.
Cette action peut résoudre l'erreur 3079 (quota insuffisant).

Après cette opération, redémarrez le service WSearch.

Voulez-vous continuer ?
"@

    $res = [System.Windows.MessageBox]::Show($warning, "Réinitialiser USN", "YesNo", "Warning")
    if ($res -ne "Yes") { return }

    Set-Status "Réinitialisation du journal USN..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $result = Reset-USNJournal -Volume "C:"
        if ($result.Success) {
            Set-Status $result.Message
            [System.Windows.MessageBox]::Show($result.Message, "Succès", "OK", "Information") | Out-Null
        } else {
            Set-Status "Erreur: $($result.Message)"
            [System.Windows.MessageBox]::Show($result.Message, "Erreur", "OK", "Error") | Out-Null
        }
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    } finally {
        $window.Cursor = $null
    }
})

$BtnStopWSearchMaint.Add_Click({
    try {
        Stop-WSearch
        Set-Status "Service WSearch arrêté."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnStartWSearchMaint.Add_Click({
    try {
        Start-WSearch
        Set-Status "Service WSearch démarré."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

$BtnRestartWSearchMaint.Add_Click({
    try {
        Restart-WSearch
        Set-Status "Service WSearch redémarré."
    } catch {
        Set-Status "Erreur: $($_.Exception.Message)"
        [System.Windows.MessageBox]::Show($_.Exception.Message, "Erreur", "OK", "Error") | Out-Null
    }
})

# -------------------------
# Start
# -------------------------
Update-ProfileSelector
Set-Status "Prêt."
$TxtHint.Text = ""
$window.ShowDialog() | Out-Null
