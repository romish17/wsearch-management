#Requires -Version 5.1
<#
WSearchRemote.ps1 - Gestion distante de Windows Search (WPF GUI)
- Connexion unique via Get-Credential (stockée pour toute la session)
- Gestion de plusieurs serveurs simultanément via PSSessions persistantes
- Tab 1: Vue d'ensemble  (statut WSearch + OS + éléments indexés sur tous les serveurs)
- Tab 2: Tweaks          (registre Windows Search / Policies en remote)
- Tab 3: Service         (Démarrer / Arrêter / Redémarrer / Changer StartType)
- Tab 4: Bases EDB       (taille et présence des fichiers index .edb)
- Tab 5: Maintenance     (rebuild index, nettoyage catalogues per-user, journal USN)
- Tab 6: Logs            (événements Windows Search distants - Event Viewer)
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml

# ─────────────────────────────────────────
# Global state
# ─────────────────────────────────────────
$script:Credential   = $null
$script:Sessions     = @{}   # [string]ComputerName -> PSSession

$script:ServerList   = [System.Collections.ObjectModel.ObservableCollection[string]]::new()
$script:OverviewRows = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:TweakRows    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:EdbRows      = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:LogRows      = [System.Collections.ObjectModel.ObservableCollection[object]]::new()

# ─────────────────────────────────────────
# Registry settings catalog (Windows Search)
# ─────────────────────────────────────────
$SearchSettings = @(
    [pscustomobject]@{
        DisplayName = "DisableBackoff"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "DisableBackoff"
        Recommended = "0"
        Description = "0=backoff actif (moins agressif, économise ressources). 1=désactivé."
    },
    [pscustomobject]@{
        DisplayName = "ConnectedSearchUseWeb"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "ConnectedSearchUseWeb"
        Recommended = "0"
        Description = "0=coupe résultats Web/Bing (économise bande passante)."
    },
    [pscustomobject]@{
        DisplayName = "EnableDynamicContentInWSB"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "EnableDynamicContentInWSB"
        Recommended = "0"
        Description = "0=désactive contenus dynamiques/highlights (économise ressources)."
    },
    [pscustomobject]@{
        DisplayName = "PreventRemoteQueries"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "PreventRemoteQueries"
        Recommended = "1"
        Description = "1=empêche requêtes distantes sur l'index (sécurité)."
    },
    [pscustomobject]@{
        DisplayName = "DisableRemovableDriveIndexing"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "DisableRemovableDriveIndexing"
        Recommended = "1"
        Description = "1=pas d'indexation sur supports amovibles (économise ressources)."
    },
    [pscustomobject]@{
        DisplayName = "AllowCloudSearch"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AllowCloudSearch"
        Recommended = "0"
        Description = "0=coupe la recherche cloud (économise bande passante)."
    },
    [pscustomobject]@{
        DisplayName = "AllowSearchToUseLocation"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AllowSearchToUseLocation"
        Recommended = "0"
        Description = "0=désactive usage localisation (confidentialité)."
    },
    [pscustomobject]@{
        DisplayName = "AllowCortana"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AllowCortana"
        Recommended = "0"
        Description = "0=désactive Cortana (économise ressources)."
    },
    [pscustomobject]@{
        DisplayName = "AllowCortanaAboveLock"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AllowCortanaAboveLock"
        Recommended = "0"
        Description = "0=empêche Cortana sur écran verrouillé (sécurité)."
    },
    [pscustomobject]@{
        DisplayName = "AllowIndexingEncryptedStoresOrItems"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AllowIndexingEncryptedStoresOrItems"
        Recommended = "0"
        Description = "0=pas d'indexation des fichiers chiffrés (ressources)."
    },
    [pscustomobject]@{
        DisplayName = "PreventIndexingOutlook"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "PreventIndexingOutlook"
        Recommended = "1"
        Description = "1=empêche indexation Microsoft Outlook (économise ressources)."
    },
    [pscustomobject]@{
        DisplayName = "PreventIndexingEmailAttachments"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "PreventIndexingEmailAttachments"
        Recommended = "1"
        Description = "1=empêche indexation pièces jointes (économise ressources)."
    },
    [pscustomobject]@{
        DisplayName = "AutoAddShares"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "AutoAddShares"
        Recommended = "0"
        Description = "0=empêche ajout automatique de partages réseau à l'index."
    },
    [pscustomobject]@{
        DisplayName = "ConnectedSearchUseWebOverMeteredConnections"
        KeyPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        ValueName   = "ConnectedSearchUseWebOverMeteredConnections"
        Recommended = "0"
        Description = "0=pas de recherche Web sur connexions limitées."
    },
    [pscustomobject]@{
        DisplayName = "EnablePerUserCatalog"
        KeyPath     = "HKLM:\SOFTWARE\Microsoft\Windows Search"
        ValueName   = "EnablePerUserCatalog"
        Recommended = "0"
        Description = "1=index par utilisateur. Déconseillé avec profils roaming/FSLogix."
    }
)

# ─────────────────────────────────────────
# Session helpers
# ─────────────────────────────────────────
function Test-SessionOpen([string]$Computer) {
    $s = $script:Sessions[$Computer]
    return ($null -ne $s -and $s.State -eq 'Opened')
}

function Connect-Server([string]$Computer) {
    if (Test-SessionOpen $Computer) { return $true }
    if (-not $script:Credential) {
        Set-Status "Aucune credential définie. Cliquez sur 'Connexion' d'abord."
        return $false
    }
    try {
        $s = New-PSSession -ComputerName $Computer -Credential $script:Credential `
                           -ErrorAction Stop
        $script:Sessions[$Computer] = $s
        return $true
    } catch {
        Set-Status "Echec connexion ${Computer}: $($_.Exception.Message)"
        return $false
    }
}

function Disconnect-Server([string]$Computer) {
    if ($script:Sessions.ContainsKey($Computer)) {
        try { Remove-PSSession $script:Sessions[$Computer] -ErrorAction SilentlyContinue } catch {}
        $script:Sessions.Remove($Computer)
    }
}

function Invoke-RemoteBlock([string]$Computer, [scriptblock]$Block, [object[]]$Args) {
    if (-not (Test-SessionOpen $Computer)) {
        Set-Status "Serveur $Computer non connecté."
        return $null
    }
    try {
        return Invoke-Command -Session $script:Sessions[$Computer] `
                              -ScriptBlock $Block -ArgumentList $Args -ErrorAction Stop
    } catch {
        Set-Status "Erreur sur ${Computer}: $($_.Exception.Message)"
        return $null
    }
}

# ─────────────────────────────────────────
# Status bar helper
# ─────────────────────────────────────────
function Set-Status([string]$Msg) {
    if ($script:StatusLabel) {
        $script:StatusLabel.Dispatcher.Invoke([action]{
            $script:StatusLabel.Content = $Msg
        })
    }
}

# ─────────────────────────────────────────
# Overview refresh
# ─────────────────────────────────────────
function Refresh-Overview {
    $script:OverviewRows.Clear()
    foreach ($computer in $script:ServerList) {
        $connected = Test-SessionOpen $computer
        $row = [pscustomobject]@{
            Serveur   = $computer
            Statut    = if ($connected) { "Connecté" } else { "Déconnecté" }
            OS        = "-"
            WSearch   = "-"
            StartType = "-"
            Indexés   = "-"
        }
        if ($connected) {
            $info = Invoke-RemoteBlock $computer {
                $svc = Get-Service -Name WSearch -ErrorAction SilentlyContinue
                $os  = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
                $indexed = try {
                    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Search\Gathering Manager" `
                                     -ErrorAction SilentlyContinue).StartedItems
                } catch { $null }
                [pscustomobject]@{
                    OS        = if ($os) { $os } else { "N/A" }
                    Status    = if ($svc) { $svc.Status.ToString() } else { "N/A" }
                    StartType = if ($svc) { $svc.StartType.ToString() } else { "N/A" }
                    Indexed   = if ($null -ne $indexed) { $indexed.ToString() } else { "N/A" }
                }
            }
            if ($info) {
                $row.OS        = $info.OS
                $row.WSearch   = $info.Status
                $row.StartType = $info.StartType
                $row.Indexés   = $info.Indexed
            }
        }
        $script:OverviewRows.Add($row)
    }
    Set-Status "Vue d'ensemble rafraîchie ($(Get-Date -Format 'HH:mm:ss'))"
}

# ─────────────────────────────────────────
# Tweaks refresh (pour un serveur donné)
# ─────────────────────────────────────────
function Refresh-Tweaks([string]$Computer) {
    $script:TweakRows.Clear()
    if (-not (Test-SessionOpen $Computer)) {
        Set-Status "Serveur $Computer non connecté."
        return
    }
    $keyPaths   = $SearchSettings | ForEach-Object { $_.KeyPath }
    $valueNames = $SearchSettings | ForEach-Object { $_.ValueName }

    $remoteValues = Invoke-RemoteBlock $Computer {
        param($kps, $vns)
        $out = @{}
        for ($i = 0; $i -lt $kps.Count; $i++) {
            $key = $kps[$i]; $name = $vns[$i]
            $val = $null
            if (Test-Path $key) {
                try {
                    $p = Get-ItemProperty -Path $key -ErrorAction Stop
                    if ($p.PSObject.Properties.Name -contains $name) { $val = [int]$p.$name }
                } catch {}
            }
            $out["$key|$name"] = $val
        }
        $out
    } @($keyPaths, $valueNames)

    foreach ($s in $SearchSettings) {
        $k   = "$($s.KeyPath)|$($s.ValueName)"
        $cur = if ($remoteValues -and $remoteValues.ContainsKey($k)) { $remoteValues[$k] } else { $null }
        $curTxt = if ($null -eq $cur) { "(Absent)" } else { "$cur" }
        $script:TweakRows.Add([pscustomobject]@{
            Paramètre   = $s.DisplayName
            Valeur      = $curTxt
            Recommandé  = $s.Recommended
            Description = $s.Description
            KeyPath     = $s.KeyPath
            ValueName   = $s.ValueName
        })
    }
    Set-Status "Tweaks chargés depuis $Computer"
}

# ─────────────────────────────────────────
# EDB scan (pour un serveur)
# ─────────────────────────────────────────
function Refresh-Edb([string]$Computer) {
    $script:EdbRows.Clear()
    if (-not (Test-SessionOpen $Computer)) {
        Set-Status "Serveur $Computer non connecté."
        return
    }
    $rows = Invoke-RemoteBlock $Computer {
        $result = @()
        # Global EDB
        $globalPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        if (Test-Path $globalPath) {
            $fi = Get-Item $globalPath -ErrorAction SilentlyContinue
            $result += [pscustomobject]@{
                Portée     = "Global"
                Utilisateur= "(Machine)"
                Chemin     = $fi.FullName
                TailleMB   = [math]::Round($fi.Length / 1MB, 2)
                Modifié    = $fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            }
        } else {
            $result += [pscustomobject]@{
                Portée     = "Global"
                Utilisateur= "(Machine)"
                Chemin     = "(Introuvable) $globalPath"
                TailleMB   = 0
                Modifié    = "-"
            }
        }
        # Per-user EDB
        $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }
        foreach ($p in $profiles) {
            $root = Join-Path $p.FullName "AppData\Roaming\Microsoft\Search\Data\Applications"
            if (-not (Test-Path $root)) { continue }
            $edbs = Get-ChildItem $root -Filter "*.edb" -Recurse -ErrorAction SilentlyContinue
            foreach ($edb in $edbs) {
                $result += [pscustomobject]@{
                    Portée     = "Per-user"
                    Utilisateur= $p.Name
                    Chemin     = $edb.FullName
                    TailleMB   = [math]::Round($edb.Length / 1MB, 2)
                    Modifié    = $edb.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                }
            }
        }
        $result
    }
    if ($rows) {
        foreach ($r in $rows) { $script:EdbRows.Add($r) }
    }
    Set-Status "Bases EDB chargées depuis $Computer"
}

# ─────────────────────────────────────────
# Logs refresh (pour un serveur)
# ─────────────────────────────────────────
function Refresh-Logs([string]$Computer, [int]$MaxEvents = 100) {
    $script:LogRows.Clear()
    if (-not (Test-SessionOpen $Computer)) {
        Set-Status "Serveur $Computer non connecté."
        return
    }
    $events = Invoke-RemoteBlock $Computer {
        param($max)
        Get-WinEvent -LogName "Application" -MaxEvents $max -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -like "*Search*" -or $_.ProviderName -like "*Windows Search*" } |
            Select-Object -First $max TimeCreated, Id, LevelDisplayName, ProviderName,
                @{ N='Message'; E={ $_.Message -replace "`r`n"," " | Select-Object -First 1 } }
    } @($MaxEvents)
    if ($events) {
        foreach ($e in $events) {
            $script:LogRows.Add([pscustomobject]@{
                Date        = if ($e.TimeCreated) { $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "-" }
                ID          = $e.Id
                Niveau      = $e.LevelDisplayName
                Source      = $e.ProviderName
                Message     = if ($e.Message) { ($e.Message -split "`n")[0].Trim() } else { "" }
            })
        }
    }
    Set-Status "Logs chargés depuis $Computer ($($script:LogRows.Count) événements)"
}

# ─────────────────────────────────────────
# XAML Definition
# ─────────────────────────────────────────
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Search - Gestion Distante"
        Width="1200" Height="780" MinWidth="900" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="12">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="Margin" Value="3"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="GroupBox">
            <Setter Property="Padding" Value="6"/>
            <Setter Property="Margin" Value="4"/>
        </Style>
        <Style TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AlternatingRowBackground" Value="#F5F5F5"/>
            <Setter Property="CanUserResizeRows" Value="False"/>
        </Style>
    </Window.Resources>

    <DockPanel>
        <!-- ═══ TOP BAR: Credential + serveur ═══ -->
        <Border DockPanel.Dock="Top" Background="#1C3A6E" Padding="10,6">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Identifiants :" Foreground="White" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
                    <TextBlock x:Name="LblCredential" Text="Non définis" Foreground="#FFBB44"
                               VerticalAlignment="Center" FontWeight="Bold" Margin="0,0,10,0"/>
                    <Button x:Name="BtnCredential" Content="Se connecter (Get-Credential)"
                            Background="#2E6DA4" Foreground="White" BorderBrush="#5090CC"/>
                    <Button x:Name="BtnClearCred" Content="Déconnecter tout"
                            Background="#7A2020" Foreground="White" BorderBrush="#AA4444"/>
                </StackPanel>
                <TextBlock Grid.Column="3" Foreground="#8BB8E8" FontSize="11"
                           Text="Windows Search Remote Manager" VerticalAlignment="Center" FontStyle="Italic"/>
            </Grid>
        </Border>

        <!-- ═══ STATUS BAR ═══ -->
        <Border DockPanel.Dock="Bottom" Background="#EEEEEE" BorderBrush="#CCCCCC"
                BorderThickness="0,1,0,0" Padding="8,3">
            <Label x:Name="LblStatus" Content="Prêt." FontSize="11" Padding="0"/>
        </Border>

        <!-- ═══ BODY: Left server panel + Right tabs ═══ -->
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="210" MinWidth="160" MaxWidth="320"/>
                <ColumnDefinition Width="4"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- ── Left panel: Server list ── -->
            <DockPanel Grid.Column="0" Background="#F0F4FA">
                <Border DockPanel.Dock="Top" Background="#2E5FA3" Padding="8,5">
                    <TextBlock Text="Serveurs" Foreground="White" FontWeight="SemiBold"/>
                </Border>

                <!-- Add server -->
                <Grid DockPanel.Dock="Top" Margin="4,4,4,2">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="TxtNewServer" Grid.Column="0"
                             ToolTip="Nom ou IP du serveur"
                             VerticalContentAlignment="Center" Padding="4,2"/>
                    <Button x:Name="BtnAddServer" Grid.Column="1" Content="+"
                            Width="28" FontWeight="Bold" Padding="0" Margin="2,3"/>
                </Grid>

                <!-- Server listbox -->
                <ListBox x:Name="LstServers" DockPanel.Dock="Top"
                         Margin="4,2,4,2" Height="280"
                         SelectionMode="Single">
                    <ListBox.ItemTemplate>
                        <DataTemplate>
                            <TextBlock Text="{Binding}" FontFamily="Consolas" FontSize="12"/>
                        </DataTemplate>
                    </ListBox.ItemTemplate>
                </ListBox>

                <!-- Per-server actions -->
                <StackPanel DockPanel.Dock="Top" Margin="4,0,4,4">
                    <Button x:Name="BtnConnectServer" Content="Connecter le serveur"
                            HorizontalAlignment="Stretch"/>
                    <Button x:Name="BtnDisconnectServer" Content="Déconnecter"
                            HorizontalAlignment="Stretch"/>
                    <Button x:Name="BtnRemoveServer" Content="Supprimer de la liste"
                            HorizontalAlignment="Stretch" Foreground="#8B0000"/>
                </StackPanel>

                <!-- Connect all -->
                <Border DockPanel.Dock="Top" BorderBrush="#CCCCCC" BorderThickness="0,1,0,0" Padding="4,4">
                    <StackPanel>
                        <Button x:Name="BtnConnectAll" Content="Connecter TOUS les serveurs"
                                HorizontalAlignment="Stretch" Background="#1C5C1C" Foreground="White"/>
                        <Button x:Name="BtnRefreshAll" Content="Rafraîchir la vue d'ensemble"
                                HorizontalAlignment="Stretch"/>
                    </StackPanel>
                </Border>

                <!-- Import/Export -->
                <Border DockPanel.Dock="Top" BorderBrush="#CCCCCC" BorderThickness="0,1,0,0" Padding="4,4">
                    <StackPanel>
                        <TextBlock Text="Import / Export liste" FontSize="11" Foreground="#555" Margin="0,0,0,2"/>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Button x:Name="BtnImportList" Grid.Column="0" Content="Importer" FontSize="11"/>
                            <Button x:Name="BtnExportList" Grid.Column="1" Content="Exporter" FontSize="11"/>
                        </Grid>
                    </StackPanel>
                </Border>

                <TextBlock DockPanel.Dock="Bottom" Margin="6,4" FontSize="10" Foreground="#888"
                           TextWrapping="Wrap"
                           Text="Sélectionnez un serveur pour charger les onglets."/>
            </DockPanel>

            <!-- Splitter -->
            <GridSplitter Grid.Column="1" Width="4" HorizontalAlignment="Stretch"
                          Background="#CCCCCC"/>

            <!-- ── Right panel: Tabs ── -->
            <TabControl Grid.Column="2" x:Name="TabsMain" Margin="4">

                <!-- ══ Tab 1: Vue d'ensemble ══ -->
                <TabItem Header="Vue d'ensemble">
                    <DockPanel>
                        <ToolBarTray DockPanel.Dock="Top">
                            <ToolBar>
                                <Button x:Name="BtnOvRefresh" Content="Rafraîchir" ToolTip="Recharge les informations de tous les serveurs"/>
                                <Button x:Name="BtnOvConnectAll" Content="Connecter tout" ToolTip="Tente de connecter tous les serveurs listés"/>
                            </ToolBar>
                        </ToolBarTray>
                        <DataGrid x:Name="GridOverview" ItemsSource="{Binding}"
                                  Margin="4">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Serveur"    Binding="{Binding Serveur}"   Width="160"/>
                                <DataGridTextColumn Header="Statut"     Binding="{Binding Statut}"    Width="90"/>
                                <DataGridTextColumn Header="OS"         Binding="{Binding OS}"        Width="*"/>
                                <DataGridTextColumn Header="WSearch"    Binding="{Binding WSearch}"   Width="80"/>
                                <DataGridTextColumn Header="StartType"  Binding="{Binding StartType}" Width="80"/>
                                <DataGridTextColumn Header="Indexés"    Binding="{Binding Indexés}"   Width="80"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </DockPanel>
                </TabItem>

                <!-- ══ Tab 2: Tweaks ══ -->
                <TabItem Header="Tweaks">
                    <DockPanel>
                        <ToolBarTray DockPanel.Dock="Top">
                            <ToolBar>
                                <Label Content="Serveur cible :"/>
                                <TextBlock x:Name="LblTweakServer" Text="(aucun)" FontWeight="Bold"
                                           VerticalAlignment="Center" Margin="4,0"/>
                                <Separator/>
                                <Button x:Name="BtnTweakRefresh" Content="Actualiser" ToolTip="Recharge les valeurs depuis le serveur sélectionné"/>
                                <Separator/>
                                <Button x:Name="BtnTweakApply" Content="Appliquer la valeur saisie"
                                        ToolTip="Applique la valeur souhaitée sur le serveur sélectionné"/>
                                <Button x:Name="BtnTweakApplyAll" Content="Appliquer sur TOUS"
                                        Background="#1C5C1C" Foreground="White"
                                        ToolTip="Applique la valeur souhaitée sur tous les serveurs connectés"/>
                                <Button x:Name="BtnTweakRemove" Content="Supprimer la valeur"
                                        ToolTip="Supprime la valeur registry (retour au défaut Windows)"/>
                                <Separator/>
                                <Button x:Name="BtnTweakRecommended" Content="Appliquer toutes les valeurs recommandées"
                                        ToolTip="Applique les valeurs recommandées sur le serveur sélectionné"/>
                                <Button x:Name="BtnTweakRecommendedAll" Content="Recommandées sur TOUS"
                                        Background="#1C5C1C" Foreground="White"
                                        ToolTip="Applique les valeurs recommandées sur tous les serveurs connectés"/>
                            </ToolBar>
                        </ToolBarTray>

                        <!-- Value editor strip -->
                        <Border DockPanel.Dock="Top" Background="#F0F4FA" Padding="8,4"
                                BorderBrush="#C8D8F0" BorderThickness="0,0,0,1">
                            <StackPanel Orientation="Horizontal">
                                <TextBlock Text="Valeur souhaitée :" VerticalAlignment="Center" Margin="0,0,6,0"/>
                                <TextBox x:Name="TxtDesiredValue" Width="60" VerticalContentAlignment="Center"
                                         Padding="4,2" ToolTip="Saisir la valeur DWORD (entier)"/>
                                <TextBlock Text="  (laisser vide pour supprimer la clé)"
                                           FontSize="11" Foreground="#666" VerticalAlignment="Center"/>
                            </StackPanel>
                        </Border>

                        <DataGrid x:Name="GridTweaks" Margin="4">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Paramètre"   Binding="{Binding Paramètre}"   Width="250"/>
                                <DataGridTextColumn Header="Valeur actuelle" Binding="{Binding Valeur}"  Width="120"/>
                                <DataGridTextColumn Header="Recommandé"  Binding="{Binding Recommandé}"  Width="90"/>
                                <DataGridTextColumn Header="Description"  Binding="{Binding Description}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </DockPanel>
                </TabItem>

                <!-- ══ Tab 3: Service ══ -->
                <TabItem Header="Service WSearch">
                    <DockPanel>
                        <ToolBarTray DockPanel.Dock="Top">
                            <ToolBar>
                                <Label Content="Serveur cible :"/>
                                <TextBlock x:Name="LblSvcServer" Text="(aucun)" FontWeight="Bold"
                                           VerticalAlignment="Center" Margin="4,0"/>
                                <Separator/>
                                <Button x:Name="BtnSvcStart"   Content="▶ Démarrer"  ToolTip="Démarre le service WSearch sur le serveur sélectionné"/>
                                <Button x:Name="BtnSvcStop"    Content="■ Arrêter"   ToolTip="Arrête le service WSearch"/>
                                <Button x:Name="BtnSvcRestart" Content="↺ Redémarrer" ToolTip="Redémarre le service WSearch"/>
                                <Separator/>
                                <Button x:Name="BtnSvcStartAll"   Content="▶ Démarrer TOUS"   Background="#1C5C1C" Foreground="White"/>
                                <Button x:Name="BtnSvcStopAll"    Content="■ Arrêter TOUS"    Background="#7A2020" Foreground="White"/>
                                <Button x:Name="BtnSvcRestartAll" Content="↺ Redémarrer TOUS" Background="#1C5C1C" Foreground="White"/>
                                <Separator/>
                                <Label Content="StartType :"/>
                                <ComboBox x:Name="CbSvcStartType" Width="110">
                                    <ComboBoxItem>Automatic</ComboBoxItem>
                                    <ComboBoxItem>Disabled</ComboBoxItem>
                                    <ComboBoxItem>Manual</ComboBoxItem>
                                </ComboBox>
                                <Button x:Name="BtnSvcSetStartType" Content="Appliquer StartType" ToolTip="Modifie le type de démarrage sur le serveur sélectionné"/>
                                <Button x:Name="BtnSvcSetStartTypeAll" Content="StartType sur TOUS"
                                        Background="#1C5C1C" Foreground="White"/>
                            </ToolBar>
                        </ToolBarTray>

                        <DataGrid x:Name="GridService" Margin="4">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Serveur"    Binding="{Binding Serveur}"   Width="160"/>
                                <DataGridTextColumn Header="Statut"     Binding="{Binding Statut}"    Width="100"/>
                                <DataGridTextColumn Header="StartType"  Binding="{Binding StartType}" Width="100"/>
                                <DataGridTextColumn Header="Résultat"   Binding="{Binding Résultat}"  Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </DockPanel>
                </TabItem>

                <!-- ══ Tab 4: Bases EDB ══ -->
                <TabItem Header="Bases EDB">
                    <DockPanel>
                        <ToolBarTray DockPanel.Dock="Top">
                            <ToolBar>
                                <Label Content="Serveur cible :"/>
                                <TextBlock x:Name="LblEdbServer" Text="(aucun)" FontWeight="Bold"
                                           VerticalAlignment="Center" Margin="4,0"/>
                                <Separator/>
                                <Button x:Name="BtnEdbRefresh" Content="Actualiser" ToolTip="Recharge les bases EDB depuis le serveur sélectionné"/>
                                <Separator/>
                                <Button x:Name="BtnEdbDeletePerUser" Content="Supprimer les EDB per-user"
                                        Foreground="DarkRed"
                                        ToolTip="Supprime les catalogues per-user (service arrêté avant + redémarré après)"/>
                            </ToolBar>
                        </ToolBarTray>
                        <DataGrid x:Name="GridEdb" Margin="4">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Portée"      Binding="{Binding Portée}"      Width="80"/>
                                <DataGridTextColumn Header="Utilisateur" Binding="{Binding Utilisateur}" Width="140"/>
                                <DataGridTextColumn Header="Chemin"      Binding="{Binding Chemin}"      Width="*"/>
                                <DataGridTextColumn Header="Taille (MB)" Binding="{Binding TailleMB}"    Width="100"/>
                                <DataGridTextColumn Header="Modifié"     Binding="{Binding Modifié}"     Width="140"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </DockPanel>
                </TabItem>

                <!-- ══ Tab 5: Maintenance ══ -->
                <TabItem Header="Maintenance">
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Margin="10">
                            <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                                <TextBlock Text="Serveur cible : " FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <TextBlock x:Name="LblMaintServer" Text="(aucun)" FontWeight="Bold"
                                           Foreground="#1C3A6E" VerticalAlignment="Center" Margin="4,0"/>
                            </StackPanel>

                            <GroupBox Header="Index global (Windows.edb)">
                                <StackPanel>
                                    <TextBlock TextWrapping="Wrap" Margin="0,0,0,6" Foreground="#444"
                                        Text="Reconstruit l'index Windows Search global sur le serveur sélectionné. Le service est arrêté, le dossier d'index supprimé, puis le service est redémarré."/>
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="BtnRebuildIndex" Content="Rebuild Index (serveur sélectionné)"
                                                Foreground="DarkRed" FontWeight="Bold"/>
                                        <Button x:Name="BtnRebuildIndexAll" Content="Rebuild sur TOUS les serveurs"
                                                Background="#7A2020" Foreground="White" FontWeight="Bold"/>
                                    </StackPanel>
                                </StackPanel>
                            </GroupBox>

                            <GroupBox Header="Catalogues per-user (*.edb)">
                                <StackPanel>
                                    <TextBlock TextWrapping="Wrap" Margin="0,0,0,6" Foreground="#444"
                                        Text="Supprime tous les catalogues d'index per-user sous C:\Users\*\AppData\Roaming\Microsoft\Search. Utile après migration de profils ou en cas de corruption."/>
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="BtnCleanPerUser" Content="Nettoyer per-user (serveur sélectionné)"
                                                Foreground="DarkRed"/>
                                        <Button x:Name="BtnCleanPerUserAll" Content="Nettoyer sur TOUS"
                                                Background="#7A2020" Foreground="White"/>
                                    </StackPanel>
                                </StackPanel>
                            </GroupBox>

                            <GroupBox Header="Journal USN (Volume C:)">
                                <StackPanel>
                                    <TextBlock TextWrapping="Wrap" Margin="0,0,0,6" Foreground="#444"
                                        Text="Supprime et recrée le journal de modifications USN sur le volume C:. Peut résoudre certains blocages d'indexation."/>
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="BtnUsnReset" Content="Reset USN Journal (serveur sélectionné)"
                                                Foreground="DarkOrange"/>
                                        <Button x:Name="BtnUsnResetAll" Content="Reset USN sur TOUS"
                                                Background="#8B4500" Foreground="White"/>
                                    </StackPanel>
                                </StackPanel>
                            </GroupBox>

                            <GroupBox Header="Résultats">
                                <TextBox x:Name="TxtMaintLog" IsReadOnly="True" MinHeight="140"
                                         FontFamily="Consolas" FontSize="11"
                                         VerticalScrollBarVisibility="Auto"
                                         HorizontalScrollBarVisibility="Auto"
                                         TextWrapping="NoWrap"/>
                            </GroupBox>
                        </StackPanel>
                    </ScrollViewer>
                </TabItem>

                <!-- ══ Tab 6: Logs ══ -->
                <TabItem Header="Logs">
                    <DockPanel>
                        <ToolBarTray DockPanel.Dock="Top">
                            <ToolBar>
                                <Label Content="Serveur cible :"/>
                                <TextBlock x:Name="LblLogServer" Text="(aucun)" FontWeight="Bold"
                                           VerticalAlignment="Center" Margin="4,0"/>
                                <Separator/>
                                <Label Content="Nb événements :"/>
                                <ComboBox x:Name="CbLogCount" Width="70" SelectedIndex="1">
                                    <ComboBoxItem>50</ComboBoxItem>
                                    <ComboBoxItem>100</ComboBoxItem>
                                    <ComboBoxItem>200</ComboBoxItem>
                                    <ComboBoxItem>500</ComboBoxItem>
                                </ComboBox>
                                <Button x:Name="BtnLogRefresh" Content="Charger les logs"/>
                            </ToolBar>
                        </ToolBarTray>
                        <DataGrid x:Name="GridLogs" Margin="4">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Date"    Binding="{Binding Date}"    Width="150"/>
                                <DataGridTextColumn Header="ID"      Binding="{Binding ID}"      Width="50"/>
                                <DataGridTextColumn Header="Niveau"  Binding="{Binding Niveau}"  Width="80"/>
                                <DataGridTextColumn Header="Source"  Binding="{Binding Source}"  Width="160"/>
                                <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>
                    </DockPanel>
                </TabItem>

            </TabControl>
        </Grid>
    </DockPanel>
</Window>
"@

# ─────────────────────────────────────────
# Load XAML
# ─────────────────────────────────────────
$reader   = [System.Xml.XmlNodeReader]::new($xaml)
$window   = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$LblCredential      = $window.FindName("LblCredential")
$BtnCredential      = $window.FindName("BtnCredential")
$BtnClearCred       = $window.FindName("BtnClearCred")
$TxtNewServer       = $window.FindName("TxtNewServer")
$BtnAddServer       = $window.FindName("BtnAddServer")
$LstServers         = $window.FindName("LstServers")
$BtnConnectServer   = $window.FindName("BtnConnectServer")
$BtnDisconnectServer= $window.FindName("BtnDisconnectServer")
$BtnRemoveServer    = $window.FindName("BtnRemoveServer")
$BtnConnectAll      = $window.FindName("BtnConnectAll")
$BtnRefreshAll      = $window.FindName("BtnRefreshAll")
$BtnImportList      = $window.FindName("BtnImportList")
$BtnExportList      = $window.FindName("BtnExportList")
$script:StatusLabel = $window.FindName("LblStatus")
$TabsMain           = $window.FindName("TabsMain")

# Overview
$GridOverview       = $window.FindName("GridOverview")
$BtnOvRefresh       = $window.FindName("BtnOvRefresh")
$BtnOvConnectAll    = $window.FindName("BtnOvConnectAll")

# Tweaks
$LblTweakServer     = $window.FindName("LblTweakServer")
$GridTweaks         = $window.FindName("GridTweaks")
$TxtDesiredValue    = $window.FindName("TxtDesiredValue")
$BtnTweakRefresh    = $window.FindName("BtnTweakRefresh")
$BtnTweakApply      = $window.FindName("BtnTweakApply")
$BtnTweakApplyAll   = $window.FindName("BtnTweakApplyAll")
$BtnTweakRemove     = $window.FindName("BtnTweakRemove")
$BtnTweakRecommended    = $window.FindName("BtnTweakRecommended")
$BtnTweakRecommendedAll = $window.FindName("BtnTweakRecommendedAll")

# Service
$LblSvcServer       = $window.FindName("LblSvcServer")
$GridService        = $window.FindName("GridService")
$BtnSvcStart        = $window.FindName("BtnSvcStart")
$BtnSvcStop         = $window.FindName("BtnSvcStop")
$BtnSvcRestart      = $window.FindName("BtnSvcRestart")
$BtnSvcStartAll     = $window.FindName("BtnSvcStartAll")
$BtnSvcStopAll      = $window.FindName("BtnSvcStopAll")
$BtnSvcRestartAll   = $window.FindName("BtnSvcRestartAll")
$CbSvcStartType     = $window.FindName("CbSvcStartType")
$BtnSvcSetStartType    = $window.FindName("BtnSvcSetStartType")
$BtnSvcSetStartTypeAll = $window.FindName("BtnSvcSetStartTypeAll")

# EDB
$LblEdbServer       = $window.FindName("LblEdbServer")
$GridEdb            = $window.FindName("GridEdb")
$BtnEdbRefresh      = $window.FindName("BtnEdbRefresh")
$BtnEdbDeletePerUser= $window.FindName("BtnEdbDeletePerUser")

# Maintenance
$LblMaintServer     = $window.FindName("LblMaintServer")
$TxtMaintLog        = $window.FindName("TxtMaintLog")
$BtnRebuildIndex    = $window.FindName("BtnRebuildIndex")
$BtnRebuildIndexAll = $window.FindName("BtnRebuildIndexAll")
$BtnCleanPerUser    = $window.FindName("BtnCleanPerUser")
$BtnCleanPerUserAll = $window.FindName("BtnCleanPerUserAll")
$BtnUsnReset        = $window.FindName("BtnUsnReset")
$BtnUsnResetAll     = $window.FindName("BtnUsnResetAll")

# Logs
$LblLogServer       = $window.FindName("LblLogServer")
$GridLogs           = $window.FindName("GridLogs")
$CbLogCount         = $window.FindName("CbLogCount")
$BtnLogRefresh      = $window.FindName("BtnLogRefresh")

# ─────────────────────────────────────────
# Bind data sources
# ─────────────────────────────────────────
$LstServers.ItemsSource   = $script:ServerList
$GridOverview.DataContext = $script:OverviewRows
$GridOverview.ItemsSource = $script:OverviewRows
$GridTweaks.ItemsSource   = $script:TweakRows
$GridEdb.ItemsSource      = $script:EdbRows
$GridLogs.ItemsSource     = $script:LogRows

# Service grid has its own collection (refreshed on demand)
$SvcRows = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$GridService.ItemsSource = $SvcRows

# ─────────────────────────────────────────
# Helper: get currently selected server
# ─────────────────────────────────────────
function Get-SelectedServer {
    return $LstServers.SelectedItem
}

function Update-ServerLabels([string]$Computer) {
    $LblTweakServer.Text  = if ($Computer) { $Computer } else { "(aucun)" }
    $LblSvcServer.Text    = if ($Computer) { $Computer } else { "(aucun)" }
    $LblEdbServer.Text    = if ($Computer) { $Computer } else { "(aucun)" }
    $LblMaintServer.Text  = if ($Computer) { $Computer } else { "(aucun)" }
    $LblLogServer.Text    = if ($Computer) { $Computer } else { "(aucun)" }
}

function Append-MaintLog([string]$Text) {
    $TxtMaintLog.Dispatcher.Invoke([action]{
        $TxtMaintLog.AppendText("[$([datetime]::Now.ToString('HH:mm:ss'))] $Text`n")
        $TxtMaintLog.ScrollToEnd()
    })
}

# ─────────────────────────────────────────
# Maint helper: run rebuild on one server
# ─────────────────────────────────────────
function Do-RebuildIndex([string]$Computer) {
    Append-MaintLog "$Computer : Arrêt du service WSearch..."
    $r1 = Invoke-RemoteBlock $Computer {
        Stop-Service WSearch -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $dir = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"
        if (Test-Path $dir) {
            Remove-Item "$dir\*.edb" -Force -ErrorAction SilentlyContinue
            Remove-Item "$dir\*.log" -Force -ErrorAction SilentlyContinue
            Remove-Item "$dir\*.jrs" -Force -ErrorAction SilentlyContinue
            Remove-Item "$dir\*.chk" -Force -ErrorAction SilentlyContinue
            Remove-Item "$dir\GatherLogs" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Start-Service WSearch -ErrorAction SilentlyContinue
        "OK"
    }
    Append-MaintLog "$Computer : Rebuild lancé - $r1"
}

function Do-CleanPerUser([string]$Computer) {
    Append-MaintLog "$Computer : Nettoyage des catalogues per-user..."
    $r = Invoke-RemoteBlock $Computer {
        Stop-Service WSearch -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $count = 0
        $profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }
        foreach ($p in $profiles) {
            $root = Join-Path $p.FullName "AppData\Roaming\Microsoft\Search\Data\Applications"
            if (Test-Path $root) {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
                $count++
            }
        }
        Start-Service WSearch -ErrorAction SilentlyContinue
        "$count profil(s) nettoyé(s)"
    }
    Append-MaintLog "$Computer : $r"
}

function Do-UsnReset([string]$Computer) {
    Append-MaintLog "$Computer : Reset journal USN sur C:..."
    $r = Invoke-RemoteBlock $Computer {
        $out = & fsutil usn deletejournal /d C: 2>&1
        $out2 = & fsutil usn createjournal m=0x800000 a=0x100000 C: 2>&1
        "Delete: $out | Create: $out2"
    }
    Append-MaintLog "$Computer : $r"
}

function Do-ServiceAction([string]$Computer, [string]$Action, [string]$StartType = "") {
    $row = $SvcRows | Where-Object { $_.Serveur -eq $Computer }
    if (-not $row) {
        $row = [pscustomobject]@{ Serveur=$Computer; Statut="-"; StartType="-"; Résultat="-" }
        $SvcRows.Add($row)
    }
    $result = Invoke-RemoteBlock $Computer {
        param($action, $startType)
        $svc = Get-Service WSearch -ErrorAction SilentlyContinue
        if (-not $svc) { return "Service WSearch introuvable" }
        switch ($action) {
            "Start"   { Start-Service WSearch -ErrorAction SilentlyContinue }
            "Stop"    { Stop-Service  WSearch -Force -ErrorAction SilentlyContinue }
            "Restart" {
                Stop-Service  WSearch -Force -ErrorAction SilentlyContinue
                Start-Sleep 2
                Start-Service WSearch -ErrorAction SilentlyContinue
            }
            "SetType" {
                Set-Service WSearch -StartupType $startType -ErrorAction SilentlyContinue
            }
        }
        $svc = Get-Service WSearch -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        }
    } @($Action, $StartType)

    $idx = $SvcRows.IndexOf($row)
    if ($result) {
        $newRow = [pscustomobject]@{
            Serveur   = $Computer
            Statut    = $result.Status
            StartType = $result.StartType
            Résultat  = "Action '$Action' appliquée"
        }
        $SvcRows.RemoveAt($idx)
        $SvcRows.Insert($idx, $newRow)
    }
}

# ─────────────────────────────────────────
# Event handlers
# ─────────────────────────────────────────

# --- Credential ---
$BtnCredential.Add_Click({
    try {
        $cred = Get-Credential -Message "Entrez vos identifiants pour la connexion aux serveurs distants"
        if ($cred) {
            $script:Credential      = $cred
            $LblCredential.Text     = $cred.UserName
            $LblCredential.Foreground = "#44FF88"
            Set-Status "Identifiants définis pour : $($cred.UserName)"
        }
    } catch {
        Set-Status "Credential annulée."
    }
})

$BtnClearCred.Add_Click({
    $r = [System.Windows.MessageBox]::Show(
        "Déconnecter toutes les sessions et effacer les identifiants ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($computer in @($script:Sessions.Keys)) { Disconnect-Server $computer }
        $script:Credential        = $null
        $LblCredential.Text       = "Non définis"
        $LblCredential.Foreground = "#FFBB44"
        $SvcRows.Clear()
        Refresh-Overview
        Set-Status "Sessions fermées, identifiants effacés."
    }
})

# --- Server list ---
$BtnAddServer.Add_Click({
    $name = $TxtNewServer.Text.Trim()
    if ($name -and -not $script:ServerList.Contains($name)) {
        $script:ServerList.Add($name)
        $TxtNewServer.Clear()
        Set-Status "Serveur '$name' ajouté."
    }
})

$TxtNewServer.Add_KeyDown({
    if ($_.Key -eq "Return") { $BtnAddServer.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
})

$BtnRemoveServer.Add_Click({
    $sel = Get-SelectedServer
    if ($sel) {
        Disconnect-Server $sel
        $script:ServerList.Remove($sel)
        Set-Status "Serveur '$sel' supprimé."
    }
})

$BtnConnectServer.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    if (-not $script:Credential) { Set-Status "Définissez les identifiants d'abord."; return }
    Set-Status "Connexion vers $sel..."
    $ok = Connect-Server $sel
    Set-Status if ($ok) { "Connecté à $sel" } else { "Echec connexion $sel" }
    Refresh-Overview
})

$BtnDisconnectServer.Add_Click({
    $sel = Get-SelectedServer
    if ($sel) { Disconnect-Server $sel; Refresh-Overview; Set-Status "Déconnecté de $sel" }
})

$BtnConnectAll.Add_Click({
    if (-not $script:Credential) { Set-Status "Définissez les identifiants d'abord."; return }
    Set-Status "Connexion de tous les serveurs..."
    foreach ($s in $script:ServerList) { Connect-Server $s }
    Refresh-Overview
    Set-Status "Connexion de masse terminée."
})

$BtnRefreshAll.Add_Click({ Refresh-Overview })

# Server selection change → update all tab labels + load data
$LstServers.Add_SelectionChanged({
    $sel = Get-SelectedServer
    Update-ServerLabels $sel
    if ($sel) {
        # Auto-load active tab data
        switch ($TabsMain.SelectedIndex) {
            1 { Refresh-Tweaks $sel }
            3 { Refresh-Edb $sel }
            5 {
                $maxStr = ($CbLogCount.SelectedItem.Content).ToString()
                $max    = if ($maxStr) { [int]$maxStr } else { 100 }
                Refresh-Logs $sel $max
            }
        }
    }
})

# Import / Export server list
$BtnImportList.Add_Click({
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    $dlg.Filter = "Fichiers texte (*.txt)|*.txt|Tous (*.*)|*.*"
    $dlg.Title  = "Importer une liste de serveurs"
    if ($dlg.ShowDialog()) {
        $lines = Get-Content $dlg.FileName -ErrorAction SilentlyContinue |
                     Where-Object { $_.Trim() -ne "" }
        foreach ($line in $lines) {
            $n = $line.Trim()
            if ($n -and -not $script:ServerList.Contains($n)) { $script:ServerList.Add($n) }
        }
        Set-Status "$($lines.Count) serveur(s) importé(s) depuis $($dlg.FileName)"
    }
})

$BtnExportList.Add_Click({
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter   = "Fichiers texte (*.txt)|*.txt"
    $dlg.FileName = "servers.txt"
    $dlg.Title    = "Exporter la liste de serveurs"
    if ($dlg.ShowDialog()) {
        $script:ServerList | Set-Content $dlg.FileName
        Set-Status "Liste exportée vers $($dlg.FileName)"
    }
})

# ─── Overview ───
$BtnOvRefresh.Add_Click({ Refresh-Overview })
$BtnOvConnectAll.Add_Click({
    if (-not $script:Credential) { Set-Status "Définissez les identifiants d'abord."; return }
    foreach ($s in $script:ServerList) { Connect-Server $s }
    Refresh-Overview
})

# ─── Tweaks ───
$BtnTweakRefresh.Add_Click({
    $sel = Get-SelectedServer
    if ($sel) { Refresh-Tweaks $sel } else { Set-Status "Sélectionnez un serveur." }
})

$BtnTweakApply.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $row = $GridTweaks.SelectedItem
    if (-not $row) { Set-Status "Sélectionnez un paramètre dans la grille."; return }
    $val = $TxtDesiredValue.Text.Trim()
    if ($val -eq "") { Set-Status "Entrez une valeur entière dans le champ 'Valeur souhaitée'."; return }
    if (-not [int]::TryParse($val, [ref]$null)) { Set-Status "Valeur invalide (entier requis)."; return }
    Invoke-RemoteBlock $sel {
        param($path, $name, $v)
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value ([int]$v) -Force | Out-Null
    } @($row.KeyPath, $row.ValueName, [int]$val)
    Refresh-Tweaks $sel
    Set-Status "Valeur $($row.ValueName)=$val appliquée sur $sel"
})

$BtnTweakApplyAll.Add_Click({
    $row = $GridTweaks.SelectedItem
    if (-not $row) { Set-Status "Sélectionnez un paramètre dans la grille."; return }
    $val = $TxtDesiredValue.Text.Trim()
    if (-not [int]::TryParse($val, [ref]$null)) { Set-Status "Valeur invalide."; return }
    foreach ($s in $script:ServerList) {
        if (Test-SessionOpen $s) {
            Invoke-RemoteBlock $s {
                param($path, $name, $v)
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value ([int]$v) -Force | Out-Null
            } @($row.KeyPath, $row.ValueName, [int]$val)
        }
    }
    $sel = Get-SelectedServer
    if ($sel) { Refresh-Tweaks $sel }
    Set-Status "Valeur $($row.ValueName)=$val appliquée sur tous les serveurs connectés."
})

$BtnTweakRemove.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $row = $GridTweaks.SelectedItem
    if (-not $row) { Set-Status "Sélectionnez un paramètre."; return }
    Invoke-RemoteBlock $sel {
        param($path, $name)
        if (Test-Path $path) {
            try { Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction Stop } catch {}
        }
    } @($row.KeyPath, $row.ValueName)
    Refresh-Tweaks $sel
    Set-Status "Valeur $($row.ValueName) supprimée sur $sel"
})

$BtnTweakRecommended.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Appliquer toutes les valeurs recommandées sur $sel ?",
        "Confirmation", "YesNo", "Question")
    if ($r -ne "Yes") { return }
    foreach ($s in $SearchSettings) {
        if ($s.Recommended -ne "") {
            Invoke-RemoteBlock $sel {
                param($path,$name,$v)
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value ([int]$v) -Force | Out-Null
            } @($s.KeyPath, $s.ValueName, [int]$s.Recommended)
        }
    }
    Refresh-Tweaks $sel
    Set-Status "Valeurs recommandées appliquées sur $sel"
})

$BtnTweakRecommendedAll.Add_Click({
    $connected = @($script:ServerList | Where-Object { Test-SessionOpen $_ })
    if ($connected.Count -eq 0) { Set-Status "Aucun serveur connecté."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Appliquer toutes les valeurs recommandées sur $($connected.Count) serveur(s) connecté(s) ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -ne "Yes") { return }
    foreach ($comp in $connected) {
        foreach ($s in $SearchSettings) {
            if ($s.Recommended -ne "") {
                Invoke-RemoteBlock $comp {
                    param($path,$name,$v)
                    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                    New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value ([int]$v) -Force | Out-Null
                } @($s.KeyPath, $s.ValueName, [int]$s.Recommended)
            }
        }
    }
    $sel = Get-SelectedServer
    if ($sel) { Refresh-Tweaks $sel }
    Set-Status "Valeurs recommandées appliquées sur tous les serveurs connectés."
})

# ─── Service ───
function Refresh-SvcGrid {
    $SvcRows.Clear()
    foreach ($computer in $script:ServerList) {
        if (Test-SessionOpen $computer) {
            $info = Invoke-RemoteBlock $computer {
                $svc = Get-Service WSearch -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Status    = if ($svc) { $svc.Status.ToString() } else { "N/A" }
                    StartType = if ($svc) { $svc.StartType.ToString() } else { "N/A" }
                }
            }
            $SvcRows.Add([pscustomobject]@{
                Serveur   = $computer
                Statut    = if ($info) { $info.Status } else { "Erreur" }
                StartType = if ($info) { $info.StartType } else { "-" }
                Résultat  = "-"
            })
        }
    }
}

$BtnSvcStart.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    Do-ServiceAction $sel "Start"
    Set-Status "Démarrage de WSearch sur $sel"
})
$BtnSvcStop.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    Do-ServiceAction $sel "Stop"
    Set-Status "Arrêt de WSearch sur $sel"
})
$BtnSvcRestart.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    Do-ServiceAction $sel "Restart"
    Set-Status "Redémarrage de WSearch sur $sel"
})
$BtnSvcStartAll.Add_Click({
    foreach ($s in $script:ServerList) { if (Test-SessionOpen $s) { Do-ServiceAction $s "Start" } }
    Set-Status "Démarrage de WSearch sur tous les serveurs connectés."
})
$BtnSvcStopAll.Add_Click({
    $r = [System.Windows.MessageBox]::Show(
        "Arrêter WSearch sur TOUS les serveurs connectés ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($s in $script:ServerList) { if (Test-SessionOpen $s) { Do-ServiceAction $s "Stop" } }
        Set-Status "Arrêt de WSearch sur tous les serveurs connectés."
    }
})
$BtnSvcRestartAll.Add_Click({
    $r = [System.Windows.MessageBox]::Show(
        "Redémarrer WSearch sur TOUS les serveurs connectés ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($s in $script:ServerList) { if (Test-SessionOpen $s) { Do-ServiceAction $s "Restart" } }
        Set-Status "Redémarrage de WSearch sur tous les serveurs connectés."
    }
})
$BtnSvcSetStartType.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $st  = ($CbSvcStartType.SelectedItem.Content).ToString()
    Do-ServiceAction $sel "SetType" $st
    Set-Status "StartType '$st' appliqué sur $sel"
})
$BtnSvcSetStartTypeAll.Add_Click({
    $st = ($CbSvcStartType.SelectedItem.Content).ToString()
    $r  = [System.Windows.MessageBox]::Show(
        "Appliquer StartType '$st' sur TOUS les serveurs connectés ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($s in $script:ServerList) { if (Test-SessionOpen $s) { Do-ServiceAction $s "SetType" $st } }
        Set-Status "StartType '$st' appliqué sur tous les serveurs connectés."
    }
})

# Auto-refresh service grid when Service tab is selected
$TabsMain.Add_SelectionChanged({
    $sel = Get-SelectedServer
    switch ($TabsMain.SelectedIndex) {
        1 { if ($sel) { Refresh-Tweaks $sel } }
        2 { Refresh-SvcGrid }
        3 { if ($sel) { Refresh-Edb $sel } }
        5 {
            if ($sel) {
                $maxStr = ($CbLogCount.SelectedItem.Content).ToString()
                $max    = if ($maxStr) { [int]$maxStr } else { 100 }
                Refresh-Logs $sel $max
            }
        }
    }
})

# ─── EDB ───
$BtnEdbRefresh.Add_Click({
    $sel = Get-SelectedServer
    if ($sel) { Refresh-Edb $sel } else { Set-Status "Sélectionnez un serveur." }
})

$BtnEdbDeletePerUser.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Supprimer tous les catalogues per-user sur $sel ?`nLe service WSearch sera arrêté puis redémarré.",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        Do-CleanPerUser $sel
        Refresh-Edb $sel
    }
})

# ─── Maintenance ───
$BtnRebuildIndex.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Reconstruire l'index Windows Search sur $sel ?`n`nLe service sera arrêté, les fichiers index supprimés, puis le service redémarré.",
        "Rebuild Index", "YesNo", "Warning")
    if ($r -eq "Yes") { Do-RebuildIndex $sel }
})

$BtnRebuildIndexAll.Add_Click({
    $connected = @($script:ServerList | Where-Object { Test-SessionOpen $_ })
    if ($connected.Count -eq 0) { Set-Status "Aucun serveur connecté."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Reconstruire l'index sur $($connected.Count) serveur(s) connecté(s) ?",
        "Rebuild All", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($comp in $connected) { Do-RebuildIndex $comp }
    }
})

$BtnCleanPerUser.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Supprimer les catalogues per-user sur $sel ?",
        "Nettoyage per-user", "YesNo", "Warning")
    if ($r -eq "Yes") { Do-CleanPerUser $sel }
})

$BtnCleanPerUserAll.Add_Click({
    $connected = @($script:ServerList | Where-Object { Test-SessionOpen $_ })
    if ($connected.Count -eq 0) { Set-Status "Aucun serveur connecté."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Nettoyer les per-user sur $($connected.Count) serveur(s) ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($comp in $connected) { Do-CleanPerUser $comp }
    }
})

$BtnUsnReset.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Réinitialiser le journal USN sur $sel ?",
        "Reset USN", "YesNo", "Question")
    if ($r -eq "Yes") { Do-UsnReset $sel }
})

$BtnUsnResetAll.Add_Click({
    $connected = @($script:ServerList | Where-Object { Test-SessionOpen $_ })
    if ($connected.Count -eq 0) { Set-Status "Aucun serveur connecté."; return }
    $r = [System.Windows.MessageBox]::Show(
        "Reset USN sur $($connected.Count) serveur(s) ?",
        "Confirmation", "YesNo", "Warning")
    if ($r -eq "Yes") {
        foreach ($comp in $connected) { Do-UsnReset $comp }
    }
})

# ─── Logs ───
$BtnLogRefresh.Add_Click({
    $sel = Get-SelectedServer
    if (-not $sel) { Set-Status "Sélectionnez un serveur."; return }
    $maxStr = ($CbLogCount.SelectedItem.Content).ToString()
    $max    = if ($maxStr) { [int]$maxStr } else { 100 }
    Refresh-Logs $sel $max
})

# ─────────────────────────────────────────
# Cleanup on close
# ─────────────────────────────────────────
$window.Add_Closing({
    foreach ($comp in @($script:Sessions.Keys)) { Disconnect-Server $comp }
})

# ─────────────────────────────────────────
# Launch
# ─────────────────────────────────────────
[void]$window.ShowDialog()
