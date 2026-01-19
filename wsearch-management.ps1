#Requires -Version 5.1
<#
WindowsSearchTuner.ps1 - WPF GUI (Adaptive + DB Manager)
- Tab 1: Tweaks Windows Search / FSLogix (si détecté)
- Tab 2: Gestion des bases Windows Search (Global Windows.edb / Per-user *.edb)
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
# FSLogix detection
# -------------------------
$fslogixRegPresent = (Test-Path "HKLM:\SOFTWARE\FSLogix") -or (Test-Path "HKLM:\SOFTWARE\Policies\FSLogix")
$fslogixServicePresent = $false
try {
    $frx = Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue
    if ($frx) { $fslogixServicePresent = $true }
} catch { }
$hasFSLogix = ($fslogixRegPresent -or $fslogixServicePresent)

# -------------------------
# Settings catalog (Adaptive)
# -------------------------
$RawSettings = @(
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="DisableBackoff (Indexer backoff)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="DisableBackoff"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "0" }
        Description="0 = Backoff actif (moins agressif). 1 = backoff désactivé (plus agressif)."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="ConnectedSearchUseWeb (Web results)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="ConnectedSearchUseWeb"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "0" }
        Description="0 = coupe résultats Web/Bing."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="EnableDynamicContentInWSB (Search highlights)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="EnableDynamicContentInWSB"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "0" }
        Description="0 = désactive contenus dynamiques/highlights."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="PreventRemoteQueries (Remote queries)"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="PreventRemoteQueries"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "1" }
        Description="1 = empêche requêtes à distance sur l'index."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="DisableRemovableDriveIndexing"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="DisableRemovableDriveIndexing"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "1" }
        Description="1 = pas d'indexation sur supports amovibles."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="AllowCloudSearch"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="AllowCloudSearch"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "0" }
        Description="0 = coupe la recherche cloud dans la recherche Windows."
    },
    [pscustomobject]@{
        Category="Windows Search (Policies)"
        DisplayName="AllowSearchToUseLocation"
        KeyPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName="AllowSearchToUseLocation"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$false
        RecommendedDynamic={ "0" }
        Description="0 = désactive usage localisation."
    },

    [pscustomobject]@{
        Category="Windows Search (Base)"
        DisplayName="EnablePerUserCatalog"
        KeyPath="HKLM:\SOFTWARE\Microsoft\Windows Search"
        ValueName="EnablePerUserCatalog"
        Type="DWORD"
        Policy=$false
        RequiresFSLogix=$false
        RecommendedDynamic={
            if ($script:isServer -or $script:isModernBuild) { "1" } else { "" }
        }
        Description="1 = index par utilisateur (souvent pertinent en multi-session)."
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
        RecommendedDynamic={ if ($script:isModernBuild) { "0" } else { "" } }
        Description="Sur OS récents, RoamSearch est souvent inutile => 0."
    },
    [pscustomobject]@{
        Category="FSLogix"
        DisplayName="RoamSearch (ODFC Policies)"
        KeyPath="HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
        ValueName="RoamSearch"
        Type="DWORD"
        Policy=$true
        RequiresFSLogix=$true
        RecommendedDynamic={ if ($script:isModernBuild) { "0" } else { "" } }
        Description="Sur OS récents, recommandé 0."
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
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border BorderBrush="#333" BorderThickness="1" CornerRadius="6" Padding="8" Grid.Row="0" Margin="0,0,0,8">
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

                    <DataGrid x:Name="GridSettings" Grid.Row="1"
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
$BtnScanDb            = $window.FindName("BtnScanDb")
$BtnOpenDbFolder      = $window.FindName("BtnOpenDbFolder")
$BtnStopWSearch       = $window.FindName("BtnStopWSearch")
$BtnStartWSearch      = $window.FindName("BtnStartWSearch")
$BtnRestartWSearchDb  = $window.FindName("BtnRestartWSearchDb")
$BtnDeleteDb          = $window.FindName("BtnDeleteDb")

function Set-Status([string]$msg) { $TxtStatus.Text = $msg }

function Build-SystemInfoText {
    $fs = if ($script:hasFSLogix) { "FSLogix: Oui" } else { "FSLogix: Non" }
    $type = if ($script:isServer) { "Type: Server" } else { "Type: Workstation" }
    $modern = if ($script:isModernBuild) { "Build moderne: Oui (>= 17763)" } else { "Build moderne: Non (< 17763)" }
    return "$($script:osCaption) | Version $($script:osVersion) (Build $($script:osBuild)) | $type | $modern | $fs"
}

# Bind data
$UiRows = Build-UiRows
$GridSettings.ItemsSource = $UiRows
$TxtSystemInfo.Text = Build-SystemInfoText
$TxtWSearchStatus.Text = Get-WSearchStatusText

# DB datasource
$DbRows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$GridDb.ItemsSource = $DbRows

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
# Start
# -------------------------
Set-Status "Prêt."
$TxtHint.Text = ""
$window.ShowDialog() | Out-Null
