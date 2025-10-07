Add-Type -AssemblyName PresentationFramework

# ------------------------
# Define Scripts Folder
# ------------------------
$scriptFolder = Join-Path -Path $PSScriptRoot -ChildPath "scripts"
if (-not (Test-Path $scriptFolder)) {
  Write-Host "Scripts folder not found at $scriptFolder" -ForegroundColor Red
  exit 1
}

# Get all subfolders (categories)
$categories = Get-ChildItem -Path $scriptFolder -Directory | Sort-Object Name
if ($categories.Count -eq 0) {
  Write-Host "No subfolders found in $scriptFolder" -ForegroundColor Yellow
  exit 1
}

# ------------------------
# Build XAML Window
# ------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="CyberPatriot Script Runner"
        Height="500" Width="700" WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <DockPanel>
            <TabControl Name="MainTabs" DockPanel.Dock="Top"/>
            <Button Content="Run Selected" DockPanel.Dock="Bottom"
                    Margin="0,10,0,0" Width="120" Height="35" HorizontalAlignment="Right" Name="RunButton"/>
        </DockPanel>
    </Grid>
</Window>
"@

# ------------------------
# Load XAML
# ------------------------
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$Window = [Windows.Markup.XamlReader]::Load($reader)

$MainTabs = $Window.FindName("MainTabs")
$RunButton = $Window.FindName("RunButton")

# Store references to all panels for later lookup
$Panels = @{}

# ------------------------
# Dynamically Create Tabs + Checkboxes
# ------------------------
foreach ($cat in $categories) {
  # Create Tab
  $tab = New-Object System.Windows.Controls.TabItem
  $tab.Header = $cat.Name

  # Scrollable container
  $scroll = New-Object System.Windows.Controls.ScrollViewer
  $scroll.VerticalScrollBarVisibility = "Auto"

  # StackPanel for checkboxes
  $panel = New-Object System.Windows.Controls.StackPanel
  $scroll.Content = $panel
  $tab.Content = $scroll

  # Add tab
  $MainTabs.Items.Add($tab)
  $Panels[$cat.Name] = $panel

  # Add scripts as checkboxes
  $scripts = Get-ChildItem -Path $cat.FullName -Filter *.ps1 | Sort-Object Name
  foreach ($script in $scripts) {
    $cb = New-Object System.Windows.Controls.CheckBox
    $cb.Content = $script.Name
    $cb.Tag = $script.FullName
    $panel.Children.Add($cb)
  }
}

# ------------------------
# Run Selected Scripts Button
# ------------------------
$RunButton.Add_Click({
    $selectedScripts = @()

    foreach ($panel in $Panels.Values) {
      foreach ($child in $panel.Children) {
        if ($child.IsChecked) {
          $selectedScripts += $child.Tag
        }
      }
    }

    if ($selectedScripts.Count -eq 0) {
      [System.Windows.MessageBox]::Show("No scripts selected!", "Info")
      return
    }

    foreach ($s in $selectedScripts) {
      try {
        Write-Host "`nRunning $s" -ForegroundColor Cyan
        & $s
        Write-Host "$s completed successfully!" -ForegroundColor Green
      }
      catch {
        Write-Host "Error running ${s}: $_" -ForegroundColor Red
      }
    }

    [System.Windows.MessageBox]::Show("All selected scripts completed!", "Done")
  })

# ------------------------
# Show GUI
# ------------------------
$Window.ShowDialog() | Out-Null
