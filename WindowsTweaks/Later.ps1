function Set-WinUtilScheduledTask {
    <#

    .SYNOPSIS
        Enables/Disables the provided Scheduled Task

    .PARAMETER Name
        The path to the Scheduled Task

    .PARAMETER State
        The State to set the Task to

    .EXAMPLE
        Set-WinUtilScheduledTask -Name "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -State "Disabled"

    #>
    param (
        $Name,
        $State
    )

    Try{
        if($State -eq "Disabled"){
            Write-Host "Disabling Scheduled Task $Name"
            Disable-ScheduledTask -TaskName $Name -ErrorAction Stop
        }
        if($State -eq "Enabled"){
            Write-Host "Enabling Scheduled Task $Name"
            Enable-ScheduledTask -TaskName $Name -ErrorAction Stop
        }
    }
    Catch [System.Exception]{
        if($psitem.Exception.Message -like "*The system cannot find the file specified*"){
            Write-Warning "Scheduled Task $name was not Found"
        }
        Else{
            Write-Warning "Unable to set $Name due to unhandled exception"
            Write-Warning $psitem.Exception.Message
        }
    }
    Catch{
        Write-Warning "Unable to run script for $name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Invoke-WinUtilVerboseLogon {
    <#
    .SYNOPSIS
        Disables/Enables VerboseLogon Messages
    .PARAMETER Enabled
        Indicates whether to enable or disable VerboseLogon messages
    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Verbose Logon Messages"
            $value = 1
        }
        else {
            Write-Host "Disabling Verbose Logon Messages"
            $value = 0
        }
        $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $Path -Name VerboseStatus -Value $value
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
Function Invoke-WinUtilMouseAcceleration {
    <#

    .SYNOPSIS
        Enables/Disables Mouse Acceleration

    .PARAMETER DarkMoveEnabled
        Indicates the current Mouse Acceleration State

    #>
    Param($MouseAccelerationEnabled)
    Try{
        if ($MouseAccelerationEnabled -eq $false){
            Write-Host "Enabling Mouse Acceleration"
            $MouseSpeed = 1
            $MouseThreshold1 = 6
            $MouseThreshold2 = 10
        }
        else {
            Write-Host "Disabling Mouse Acceleration"
            $MouseSpeed = 0
            $MouseThreshold1 = 0
            $MouseThreshold2 = 0

        }

        $Path = "HKCU:\Control Panel\Mouse"
        Set-ItemProperty -Path $Path -Name MouseSpeed -Value $MouseSpeed
        Set-ItemProperty -Path $Path -Name MouseThreshold1 -Value $MouseThreshold1
        Set-ItemProperty -Path $Path -Name MouseThreshold2 -Value $MouseThreshold2
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Invoke-WinUtilNumLock {
    <#
    .SYNOPSIS
        Disables/Enables NumLock on startup
    .PARAMETER Enabled
        Indicates whether to enable or disable Numlock on startup
    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Numlock on startup"
            $value = 2
        }
        else {
            Write-Host "Disabling Numlock on startup"
            $value = 0
        }
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
        $Path = "HKU:\.Default\Control Panel\Keyboard"
        Set-ItemProperty -Path $Path -Name InitialKeyboardIndicators -Value $value
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
# Snap is Like tiling windows
function Invoke-WinUtilSnapFlyout {
    <#
    .SYNOPSIS
        Disables/Enables Snap Assist Flyout on startup
    .PARAMETER Enabled
        Indicates whether to enable or disable Snap Assist Flyout on startup
    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Snap Assist Flyout On startup"
            $value = 1
        }
        else {
            Write-Host "Disabling Snap Assist Flyout On startup"
            $value = 0
        }
        # taskkill.exe /F /IM "explorer.exe"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        taskkill.exe /F /IM "explorer.exe"
        Set-ItemProperty -Path $Path -Name EnableSnapAssistFlyout -Value $value
        Start-Process "explorer.exe"
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Invoke-WinUtilSnapSuggestion {
    <#
    .SYNOPSIS
        Disables/Enables Snap Assist Suggestions on startup
    .PARAMETER Enabled
        Indicates whether to enable or disable Snap Assist Suggestions on startup
    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Snap Assist Suggestion On startup"
            $value = 1
        }
        else {
            Write-Host "Disabling Snap Assist Suggestion On startup"
            $value = 0
        }
        # taskkill.exe /F /IM "explorer.exe"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        taskkill.exe /F /IM "explorer.exe"
        Set-ItemProperty -Path $Path -Name SnapAssist -Value $value
        Start-Process "explorer.exe"
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Invoke-WinUtilSnapWindow {
    <#
    .SYNOPSIS
        Disables/Enables Snapping Windows on startup
    .PARAMETER Enabled
        Indicates whether to enable or disable Snapping Windows on startup
    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Snap Windows On startup | Relogin Required"
            $value = 1
        }
        else {
            Write-Host "Disabling Snap Windows On startup | Relogin Required"
            $value = 0
        }
        $Path = "HKCU:\Control Panel\Desktop"
        Set-ItemProperty -Path $Path -Name WindowArrangementActive -Value $value
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}

# Update Programs
Function Update-WinUtilProgramWinget {

    <#

    .SYNOPSIS
        This will update all programs using Winget

    #>

    [ScriptBlock]$wingetinstall = {

        $host.ui.RawUI.WindowTitle = """Winget Install"""

        Start-Transcript $ENV:TEMP\winget-update.log -Append
        winget upgrade --all --accept-source-agreements --accept-package-agreements --scope=machine --silent

    }

    $global:WinGetInstall = Start-Process -Verb runas powershell -ArgumentList "-command invoke-command -scriptblock {$wingetinstall} -argumentlist '$($ProgramsToInstall -join ",")'" -PassThru

}
function Invoke-WPFFixesNetwork {
    <#

    .SYNOPSIS
        Resets various network configurations

    #>

    Write-Host "Resetting Network with netsh" -ForegroundColor Green

    # Reset WinSock catalog to a clean state
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    # Resets WinHTTP proxy setting to DIRECT
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    # Removes all user configured IP settings
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"

    Write-Host "Process complete. Please reboot your computer."
    Write-Host "=========================================="
    Write-Host "-- Network Configuration has been Reset --" -ForegroundColor Cyan
    Write-Host "=========================================="
}

function Invoke-WPFOOSU {
    <#
    .SYNOPSIS
        Downloads and runs OO Shutup 10
    #>
    try {
        $OOSU_filepath = "$ENV:temp\OOSU10.exe"
        $Initial_ProgressPreference = $ProgressPreference
        $ProgressPreference = "SilentlyContinue" # Disables the Progress Bar to drasticly speed up Invoke-WebRequest
        Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
        Write-Host "Starting OO Shutup 10 ..."
        Start-Process $OOSU_filepath
    }
    catch {
        Write-Host "Error Downloading and Running OO Shutup 10" -ForegroundColor Red
    }
    finally {
        $ProgressPreference = $Initial_ProgressPreference
    }
}





function Copy-ToUSB([string] $fileToCopy){
	foreach ($volume in Get-Volume) {
		if ($volume -and $volume.FileSystemLabel -ieq "ventoy") {
			$destinationPath = "$($volume.DriveLetter):\"
			#Copy-Item -Path $fileToCopy -Destination $destinationPath -Force
			# Get the total size of the file
			$totalSize = (Get-Item $fileToCopy).length

			Copy-Item -Path $fileToCopy -Destination $destinationPath -Verbose -Force -Recurse -Container -PassThru |
				ForEach-Object {
					# Calculate the percentage completed
					$completed = ($_.BytesTransferred / $totalSize) * 100

					# Display the progress bar
					Write-Progress -Activity "Copying File" -Status "Progress" -PercentComplete $completed -CurrentOperation ("{0:N2} MB / {1:N2} MB" -f ($_.BytesTransferred / 1MB), ($totalSize / 1MB))
				}

			Write-Host "File copied to Ventoy drive $($volume.DriveLetter)"
			return
		}
	}
	Write-Host "Ventoy USB Key is not inserted"
}
function Remove-WinUtilAPPX {
    <#

    .SYNOPSIS
        Removes all APPX packages that match the given name

    .PARAMETER Name
        The name of the APPX package to remove

    .EXAMPLE
        Remove-WinUtilAPPX -Name "Microsoft.Microsoft3DViewer"

    #>
    param (
        $Name
    )

    Try {
        Write-Host "Removing $Name"
        Get-AppxPackage "*$Name*" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Name*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Catch [System.Exception] {
        if ($psitem.Exception.Message -like "*The requested operation requires elevation*") {
            Write-Warning "Unable to uninstall $name due to a Security Exception"
        }
        else {
            Write-Warning "Unable to uninstall $name due to unhandled exception"
            Write-Warning $psitem.Exception.StackTrace
        }
    }
    Catch{
        Write-Warning "Unable to uninstall $name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-WinUtilDNS {
    <#

    .SYNOPSIS
        Sets the DNS of all interfaces that are in the "Up" state. It will lookup the values from the DNS.Json file

    .PARAMETER DNSProvider
        The DNS provider to set the DNS server to

    .EXAMPLE
        Set-WinUtilDNS -DNSProvider "google"

    #>
    param($DNSProvider)
    if($DNSProvider -eq "Default"){return}
    Try{
        $Adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        Write-Host "Ensuring DNS is set to $DNSProvider on the following interfaces"
        Write-Host $($Adapters | Out-String)

        Foreach ($Adapter in $Adapters){
            if($DNSProvider -eq "DHCP"){
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ResetServerAddresses
            }
            Else{
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses ("$($sync.configs.dns.$DNSProvider.Primary)", "$($sync.configs.dns.$DNSProvider.Secondary)")
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses ("$($sync.configs.dns.$DNSProvider.Primary6)", "$($sync.configs.dns.$DNSProvider.Secondary6)")
            }
        }
    }
    Catch{
        Write-Warning "Unable to set DNS Provider due to an unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}




$b = @(Content = "Remove ALL MS Store Apps - NOT RECOMMENDED",
    Description = "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!",
    category = "z__Advanced Tweaks - CAUTION",
    panel = "1",
    Order = "a028_",
    appx = [
      "Microsoft.Microsoft3DViewer",
      "Microsoft.AppConnector",
      "Microsoft.BingFinance",
      "Microsoft.BingNews",
      "Microsoft.BingSports",
      "Microsoft.BingTranslator",
      "Microsoft.BingWeather",
      "Microsoft.BingFoodAndDrink",
      "Microsoft.BingHealthAndFitness",
      "Microsoft.BingTravel",
      "Microsoft.MinecraftUWP",
      "Microsoft.GamingServices",
      "Microsoft.GetHelp",
      "Microsoft.Getstarted",
      "Microsoft.Messaging",
      "Microsoft.Microsoft3DViewer",
      "Microsoft.MicrosoftSolitaireCollection",
      "Microsoft.NetworkSpeedTest",
      "Microsoft.News",
      "Microsoft.Office.Lens",
      "Microsoft.Office.Sway",
      "Microsoft.Office.OneNote",
      "Microsoft.OneConnect",
      "Microsoft.People",
      "Microsoft.Print3D",
      "Microsoft.SkypeApp",
      "Microsoft.Wallet",
      "Microsoft.Whiteboard",
      "Microsoft.WindowsAlarms",
      "microsoft.windowscommunicationsapps",
      "Microsoft.WindowsFeedbackHub",
      "Microsoft.WindowsMaps",
      "Microsoft.WindowsPhone",
      "Microsoft.WindowsSoundRecorder",
      "Microsoft.XboxApp",
      "Microsoft.ConnectivityStore",
      "Microsoft.CommsPhone",
      "Microsoft.ScreenSketch",
      "Microsoft.Xbox.TCUI",
      "Microsoft.XboxGameOverlay",
      "Microsoft.XboxGameCallableUI",
      "Microsoft.XboxSpeechToTextOverlay",
      "Microsoft.MixedReality.Portal",
      "Microsoft.XboxIdentityProvider",
      "Microsoft.ZuneMusic",
      "Microsoft.ZuneVideo",
      "Microsoft.Getstarted",
      "Microsoft.MicrosoftOfficeHub",
      "*EclipseManager*",
      "*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
      "*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*",
      "*CandyCrush*",
      "*BubbleWitch3Saga*",
      "*Wunderlist*",
      "*Flipboard*",
      "*Twitter*",
      "*Facebook*",
      "*Royal Revolt*",
      "*Sway*",
      "*Speed Test*",
      "*Dolby*",
      "*Viber*",
      "*ACGMediaPlayer*",
      "*Netflix*",
      "*OneCalendar*",
      "*LinkedInforWindows*",
      "*HiddenCityMysteryofShadows*",
      "*Hulu*",
      "*HiddenCity*",
      "*AdobePhotoshopExpress*",
      "*HotspotShieldFreeVPN*",
      "*Microsoft.Advertising.Xaml*"
    ]
    InvokeScript = [
      "
        $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, ''Microsoft'', ''Teams'')
        $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, ''Update.exe'')

        Write-Host \"Stopping Teams process...\"
        Stop-Process -Name \"*teams*\" -Force -ErrorAction SilentlyContinue

        Write-Host \"Uninstalling Teams from AppData\\Microsoft\\Teams\"
        if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
            # Uninstall app
            $proc = Start-Process $TeamsUpdateExePath \"-uninstall -s\" -PassThru
            $proc.WaitForExit()
        }

        Write-Host \"Removing Teams AppxPackage...\"
        Get-AppxPackage \"*Teams*\" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage \"*Teams*\" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

        Write-Host \"Deleting Teams directory\"
        if ([System.IO.Directory]::Exists($TeamsPath)) {
            Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
        }

        Write-Host \"Deleting Teams uninstall registry key\"
        # Uninstall from Uninstall registry key UninstallString
        $us = (Get-ChildItem -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall, HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like ''*Teams*''}).UninstallString
        if ($us.Length -gt 0) {
            $us = ($us.Replace(''/I'', ''/uninstall '') + '' /quiet'').Replace(''  '', '' '')
            $FilePath = ($us.Substring(0, $us.IndexOf(''.exe'') + 4).Trim())
            $ProcessArgs = ($us.Substring($us.IndexOf(''.exe'') + 5).Trim().replace(''  '', '' ''))
            $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
            $proc.WaitForExit()
        }
      "
    ]
)
$f = @(Content = "Disable Telemetry",
    Description = "Disables Microsoft Telemetry. Note: This will lock many Edge Browser settings. Microsoft spies heavily on you when using the Edge browser.",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a003_",
    ScheduledTask = [
      {
        Name = "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Autochk\\Proxy",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Application Experience\\MareBackup",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Application Experience\\StartupAppTask",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
        State = "Disabled",
        OriginalState = "Enabled"
      },
      {
        Name = "Microsoft\\Windows\\Maps\\MapsUpdateTask",
        State = "Disabled",
        OriginalState = "Enabled"
      }
    ],
    registry = [
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        Type = "DWord",
        Value = "0",
        Name = "AllowTelemetry",
        OriginalValue = "1"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        OriginalValue = "1",
        Name = "AllowTelemetry",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "ContentDeliveryAllowed",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "OemPreInstalledAppsEnabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "PreInstalledAppsEnabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "PreInstalledAppsEverEnabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SilentInstalledAppsEnabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SubscribedContent-338387Enabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SubscribedContent-338388Enabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SubscribedContent-338389Enabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SubscribedContent-353698Enabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        OriginalValue = "1",
        Name = "SystemPaneSuggestionsEnabled",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Siuf\\Rules",
        OriginalValue = "0",
        Name = "NumberOfSIUFInPeriod",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        OriginalValue = "0",
        Name = "DoNotShowFeedbackNotifications",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        OriginalValue = "0",
        Name = "DisableTailoredExperiencesWithDiagnosticData",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo",
        OriginalValue = "0",
        Name = "DisabledByGroupPolicy",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",
        OriginalValue = "0",
        Name = "Disabled",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config",
        OriginalValue = "1",
        Name = "DODownloadMode",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
        OriginalValue = "1",
        Name = "fAllowToGetHelp",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\OperationStatusManager",
        OriginalValue = "0",
        Name = "EnthusiastMode",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        OriginalValue = "1",
        Name = "ShowTaskViewButton",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
        OriginalValue = "1",
        Name = "PeopleBand",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        OriginalValue = "1",
        Name = "LaunchTo",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
        OriginalValue = "0",
        Name = "LongPathsEnabled",
        Value = "1",
        Type = "DWord"
      },
      {
        _Comment = "Driver searching is a function that should be left in",
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        OriginalValue = "1",
        Name = "SearchOrderConfig",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        OriginalValue = "1",
        Name = "SystemResponsiveness",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        OriginalValue = "1",
        Name = "NetworkThrottlingIndex",
        Value = "4294967295",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Control Panel\\Desktop",
        OriginalValue = "1",
        Name = "MenuShowDelay",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Control Panel\\Desktop",
        OriginalValue = "1",
        Name = "AutoEndTasks",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        OriginalValue = "0",
        Name = "ClearPageFileAtShutdown",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SYSTEM\\ControlSet001\\Services\\Ndu",
        OriginalValue = "1",
        Name = "Start",
        Value = "2",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Control Panel\\Mouse",
        OriginalValue = "400",
        Name = "MouseHoverTime",
        Value = "400",
        Type = "String"
      },
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        OriginalValue = "20",
        Name = "IRPStackSize",
        Value = "30",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds",
        OriginalValue = "1",
        Name = "EnableFeeds",
        Value = "0",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Feeds",
        OriginalValue = "1",
        Name = "ShellFeedsTaskbarViewMode",
        Value = "2",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        OriginalValue = "1",
        Name = "HideSCAMeetNow",
        Value = "1",
        Type = "DWord"
      },
      {
        Path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement",
        OriginalValue = "1",
        Name = "ScoobeSystemSettingEnabled",
        Value = "0",
        Type = "DWord"
      }
    ],
    InvokeScript = [
      "
      bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
        If ((get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" -Name CurrentBuild).CurrentBuild -lt 22557) {
            $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
            Do {
                Start-Sleep -Milliseconds 100
                $preferences = Get-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\TaskManager\" -Name \"Preferences\" -ErrorAction SilentlyContinue
            } Until ($preferences)
            Stop-Process $taskmgr
            $preferences.Preferences[28] = 0
            Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\TaskManager\" -Name \"Preferences\" -Type Binary -Value $preferences.Preferences
        }
        Remove-Item -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}\" -Recurse -ErrorAction SilentlyContinue

        # Fix Managed by your organization in Edge if regustry path exists then remove it

        If (Test-Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\") {
            Remove-Item -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\" -Recurse -ErrorAction SilentlyContinue
        }

        # Group svchost.exe processes
        $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
        Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\" -Name \"SvcHostSplitThresholdInKB\" -Type DWord -Value $ram -Force

        $autoLoggerDir = \"$env:PROGRAMDATA\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger\"
        If (Test-Path \"$autoLoggerDir\\AutoLogger-Diagtrack-Listener.etl\") {
            Remove-Item \"$autoLoggerDir\\AutoLogger-Diagtrack-Listener.etl\"
        }
        icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

        # Disable Defender Auto Sample Submission
        Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue | Out-Null
        "
    ]
)





$f = @(Content = "Set Hibernation as default (good for laptops)",
    Description = "Most modern laptops have connected stadby enabled which drains the battery, this sets hibernation as default which will not drain the battery. See issue https://github.com/ChrisTitusTech/winutil/issues/1399",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a014_",
    registry = [
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
        OriginalValue = "1",
        Name = "Attributes",
        Value = "2",
        Type = "DWord"
      },
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab\\94ac6d29-73ce-41a6-809f-6363ba21b47e",
        OriginalValue = "0",
        Name = "Attributes ",
        Value = "2",
        Type = "DWord"
      }
    ],
    InvokeScript = [
      "
      Write-Host \"Turn on Hibernation\"
      Start-Process -FilePath powercfg -ArgumentList \"/hibernate on\" -NoNewWindow -Wait

      # Set hibernation as the default action
      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-ac 60\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-dc 60\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-ac 10\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-dc 1\" -NoNewWindow -Wait
      "
    ],
    UndoScript = [
      "
      Write-Host \"Turn off Hibernation\"
      Start-Process -FilePath powercfg -ArgumentList \"/hibernate off\" -NoNewWindow -Wait

      # Set standby to detault values
      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-ac 15\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change standby-timeout-dc 15\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-ac 15\" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList \"/change monitor-timeout-dc 15\" -NoNewWindow -Wait
      "
    ]
)
$f = @(Content = "Disable Hibernation",
    Description = "Hibernation is really meant for laptops as it saves what&#39;s in memory before turning the pc off. It really should never be used, but some people are lazy and rely on it. Don&#39;t be like Bob. Bob likes hibernation.",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a005_",
    registry = [
      {
        Path = "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Power",
        Name = "HibernateEnabled",
        Type = "DWord",
        Value = "0",
        OriginalValue = "1"
      },
      {
        Path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings",
        Name = "ShowHibernateOption",
        Type = "DWord",
        Value = "0",
        OriginalValue = "1"
      }
    ],
    InvokeScript = [
      "powercfg.exe /hibernate off"
    ],
    UndoScript = [
      "powercfg.exe /hibernate on"
    ]
)
$f = @(Content = "NFS - Network File System",
    Description = "Network File System (NFS) is a mechanism for storing files on a network.",
    category = "Features",
    panel = "1",
    Order = "a014_",
    feature = [
      "ServicesForNFS-ClientOnly",
      "ClientForNFS-Infrastructure",
      "NFS-Administration"
    ],
    InvokeScript = [
      "nfsadmin client stop",
      "Set-ItemProperty -Path ''HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default'' -Name ''AnonymousUID'' -Type DWord -Value 0",
      "Set-ItemProperty -Path ''HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default'' -Name ''AnonymousGID'' -Type DWord -Value 0",
      "nfsadmin client start",
      "nfsadmin client localhost config fileaccess=755 SecFlavors=+sys -krb5 -krb5i"
    ]
)

$f = @(Content = "Enable/Disable Search Box Web Suggestions in Registry(explorer restart)",
    Description = "Enables web suggestions when searching using Windows Search.",
    category = "Features",
    panel = "1",
    Order = "a015_",
    feature = [],
    InvokeScript = [
      "
      If (!(Test-Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'')) {
            New-Item -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Name ''DisableSearchBoxSuggestions'' -Type DWord -Value 0 -Force
      Stop-Process -name explorer -force
      "
    ]
  
  



Content = "Disable Search Box Web Suggestions in Registry(explorer restart)",
    Description = "Disables web suggestions when searching using Windows Search.",
    category = "Features",
    panel = "1",
    Order = "a016_",
    feature = [],
    InvokeScript = [
      "
      If (!(Test-Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'')) {
            New-Item -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Name ''DisableSearchBoxSuggestions'' -Type DWord -Value 1 -Force
      Stop-Process -name explorer -force
      "
    ]
)
$f = @(Content = "Enable Daily Registry Backup Task 12.30am",
    Description = "Enables daily registry backup, previously disabled by Microsoft in Windows 10 1803.",
    category = "Features",
    panel = "1",
    Order = "a017_",
    feature = [],
    InvokeScript = [
      "
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager'' -Name ''EnablePeriodicBackup'' -Type DWord -Value 1 -Force
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager'' -Name ''BackupCount'' -Type DWord -Value 2 -Force
      $action = New-ScheduledTaskAction -Execute ''schtasks'' -Argument ''/run /i /tn \"\\Microsoft\\Windows\\Registry\\RegIdleBackup\"''
      $trigger = New-ScheduledTaskTrigger -Daily -At 00:30
      Register-ScheduledTask -Action $action -Trigger $trigger -TaskName ''AutoRegBackup'' -Description ''Create System Registry Backups'' -User ''System''
      "
    ]
)
$f = @(Content = "Enable\Disable Legacy F8 Boot Recovery",
    Description = "Enables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    category = "Features",
    panel = "1",
    Order = "a018_",
    feature = [],
    InvokeScript = [
      "
      If (!(Test-Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'')) {
            New-Item -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Name ''Enabled'' -Type DWord -Value 1 -Force
      Start-Process -FilePath cmd.exe -ArgumentList ''/c bcdedit /Set {Current} BootMenuPolicy Legacy'' -Wait
      "
    ]

Content = "Disable Legacy F8 Boot Recovery",
    Description = "Disables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    category = "Features",
    panel = "1",
    Order = "a019_",
    feature = [],
    InvokeScript = [
      "
      If (!(Test-Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'')) {
            New-Item -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Name ''Enabled'' -Type DWord -Value 0 -Force
      Start-Process -FilePath cmd.exe -ArgumentList ''/c bcdedit /Set {Current} BootMenuPolicy Standard'' -Wait
      "
    ]
)
$f = @(Content = "Windows Sandbox",
    category = "Features",
    panel = "1",
    Order = "a021_",
    Description = "Windows Sandbox is a lightweight virtual machine that provides a temporary desktop environment to safely run applications and programs in isolation."
)
$f = @(Content = "Disable Teredo",
    Description = "Teredo network tunneling is a ipv6 feature that can cause additional latency.",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a005_",
    registry = [
      {
        Path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        Name = "DisabledComponents",
        Value = "1",
        OriginalValue = "0",
        Type = "DWord"
      }
    ],
    InvokeScript = [
      "netsh interface teredo set state disabled"
    ],
    UndoScript = [
      "netsh interface teredo set state default"
    ]
)
$f = @(Content = "Delete Temporary Files",
    Description = "Erases TEMP Folders",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a002_",
    InvokeScript = [
      "Get-ChildItem -Path \"C:\\Windows\\Temp\" *.* -Recurse | Remove-Item -Force -Recurse
    Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse"
    ]
)
$f = @(Content = "Run Disk Cleanup",
    Description = "Runs Disk Cleanup on Drive C: and removes old Windows Updates.",
    category = "Essential Tweaks",
    panel = "1",
    Order = "a009_",
    InvokeScript = [
      "
      cleanmgr.exe /d C: /VERYLOWDISK
      Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
      "
    ]
)

$f = @(Content = "Disable Microsoft Copilot",
    Description = "Disables MS Copilot AI built into Windows since 23H2.",
    category = "z__Advanced Tweaks - CAUTION",
    panel = "1",
    Order = "a025_",
    registry = [
      {
        Path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        Name = "TurnOffWindowsCopilot",
        Type = "DWord",
        Value = "1",
        OriginalValue = "0"
      },
      {
        Path = "HKCU:\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        Name = "TurnOffWindowsCopilot",
        Type = "DWord",
        Value = "1",
        OriginalValue = "0"
      },
      {
        Path = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        Name = "ShowCopilotButton",
        Type = "DWord",
        Value = "0",
        OriginalValue = "1"
      }
    ],
    InvokeScript = [
      "
      Write-Host \"Remove Copilot\"
      dism /online /remove-package /package-name:Microsoft.Windows.Copilot
      "
    ],
    UndoScript = [
      "
      Write-Host \"Install Copilot\"
      dism /online /add-package /package-name:Microsoft.Windows.Copilot
      "
    ]
)

$f = @(Content = "Create Restore Point",
    Description = "Creates a restore point at runtime in case a revert is needed from WinUtil modifications",
    category = "Essential Tweaks",
    panel = "1",
    Checked = "False",
    Order = "a001_",
    InvokeScript = [
      "
        # Check if the user has administrative privileges
        if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host \"Please run this script as an administrator.\"
            return
        }

        # Check if System Restore is enabled for the main drive
        try {
            # Try getting restore points to check if System Restore is enabled
            Enable-ComputerRestore -Drive \"$env:SystemDrive\"
        } catch {
            Write-Host \"An error occurred while enabling System Restore: $_\"
        }

        # Check if the SystemRestorePointCreationFrequency value exists
        $exists = Get-ItemProperty -path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -Name \"SystemRestorePointCreationFrequency\" -ErrorAction SilentlyContinue
        if($null -eq $exists){
            write-host ''Changing system to allow multiple restore points per day''
            Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" -Name \"SystemRestorePointCreationFrequency\" -Value \"0\" -Type DWord -Force -ErrorAction Stop | Out-Null
        }

        # Attempt to load the required module for Get-ComputerRestorePoint
        try {
            Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
        } catch {
            Write-Host \"Failed to load the Microsoft.PowerShell.Management module: $_\"
            return
        }

        # Get all the restore points for the current day
        try {
            $existingRestorePoints = Get-ComputerRestorePoint | Where-Object { $_.CreationTime.Date -eq (Get-Date).Date }
        } catch {
            Write-Host \"Failed to retrieve restore points: $_\"
            return
        }

        # Check if there is already a restore point created today
        if ($existingRestorePoints.Count -eq 0) {
            $description = \"System Restore Point created by WinUtil\"

            Checkpoint-Computer -Description $description -RestorePointType \"MODIFY_SETTINGS\"
            Write-Host -ForegroundColor Green \"System Restore Point Created Successfully\"
        }
      "
    ]
)
$f = @(Content = "Remove ALL MS Store Apps - NOT RECOMMENDED",
    Description = "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!",
    category = "z__Advanced Tweaks - CAUTION",
    panel = "1",
    Order = "a028_",
    appx = [
      "Microsoft.Microsoft3DViewer",
      "Microsoft.AppConnector",
      "Microsoft.BingFinance",
      "Microsoft.BingNews",
      "Microsoft.BingSports",
      "Microsoft.BingTranslator",
      "Microsoft.BingWeather",
      "Microsoft.BingFoodAndDrink",
      "Microsoft.BingHealthAndFitness",
      "Microsoft.BingTravel",
      "Microsoft.MinecraftUWP",
      "Microsoft.GamingServices",
      "Microsoft.GetHelp",
      "Microsoft.Getstarted",
      "Microsoft.Messaging",
      "Microsoft.Microsoft3DViewer",
      "Microsoft.MicrosoftSolitaireCollection",
      "Microsoft.NetworkSpeedTest",
      "Microsoft.News",
      "Microsoft.Office.Lens",
      "Microsoft.Office.Sway",
      "Microsoft.Office.OneNote",
      "Microsoft.OneConnect",
      "Microsoft.People",
      "Microsoft.Print3D",
      "Microsoft.SkypeApp",
      "Microsoft.Wallet",
      "Microsoft.Whiteboard",
      "Microsoft.WindowsAlarms",
      "microsoft.windowscommunicationsapps",
      "Microsoft.WindowsFeedbackHub",
      "Microsoft.WindowsMaps",
      "Microsoft.WindowsPhone",
      "Microsoft.WindowsSoundRecorder",
      "Microsoft.XboxApp",
      "Microsoft.ConnectivityStore",
      "Microsoft.CommsPhone",
      "Microsoft.ScreenSketch",
      "Microsoft.Xbox.TCUI",
      "Microsoft.XboxGameOverlay",
      "Microsoft.XboxGameCallableUI",
      "Microsoft.XboxSpeechToTextOverlay",
      "Microsoft.MixedReality.Portal",
      "Microsoft.XboxIdentityProvider",
      "Microsoft.ZuneMusic",
      "Microsoft.ZuneVideo",
      "Microsoft.Getstarted",
      "Microsoft.MicrosoftOfficeHub",
      "*EclipseManager*",
      "*ActiproSoftwareLLC*",
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
      "*Duolingo-LearnLanguagesforFree*",
      "*PandoraMediaInc*",
      "*CandyCrush*",
      "*BubbleWitch3Saga*",
      "*Wunderlist*",
      "*Flipboard*",
      "*Twitter*",
      "*Facebook*",
      "*Royal Revolt*",
      "*Sway*",
      "*Speed Test*",
      "*Dolby*",
      "*Viber*",
      "*ACGMediaPlayer*",
      "*Netflix*",
      "*OneCalendar*",
      "*LinkedInforWindows*",
      "*HiddenCityMysteryofShadows*",
      "*Hulu*",
      "*HiddenCity*",
      "*AdobePhotoshopExpress*",
      "*HotspotShieldFreeVPN*",
      "*Microsoft.Advertising.Xaml*"
    ],
    InvokeScript = [
      "
        $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, ''Microsoft'', ''Teams'')
        $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, ''Update.exe'')

        Write-Host \"Stopping Teams process...\"
        Stop-Process -Name \"*teams*\" -Force -ErrorAction SilentlyContinue

        Write-Host \"Uninstalling Teams from AppData\\Microsoft\\Teams\"
        if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
            # Uninstall app
            $proc = Start-Process $TeamsUpdateExePath \"-uninstall -s\" -PassThru
            $proc.WaitForExit()
        }

        Write-Host \"Removing Teams AppxPackage...\"
        Get-AppxPackage \"*Teams*\" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage \"*Teams*\" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

        Write-Host \"Deleting Teams directory\"
        if ([System.IO.Directory]::Exists($TeamsPath)) {
            Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
        }

        Write-Host \"Deleting Teams uninstall registry key\"
        # Uninstall from Uninstall registry key UninstallString
        $us = (Get-ChildItem -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall, HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like ''*Teams*''}).UninstallString
        if ($us.Length -gt 0) {
            $us = ($us.Replace(''/I'', ''/uninstall '') + '' /quiet'').Replace(''  '', '' '')
            $FilePath = ($us.Substring(0, $us.IndexOf(''.exe'') + 4).Trim())
            $ProcessArgs = ($us.Substring($us.IndexOf(''.exe'') + 5).Trim().replace(''  '', '' ''))
            $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
            $proc.WaitForExit()
        }
      "
    ]
)






$f = @($dns = {
  Google = {
    Primary =  "8.8.8.8",
    Secondary =  "8.8.4.4",
    Primary6 =  "2001:4860:4860::8888",
    Secondary6 =  "2001:4860:4860::8844"
}
Cloudflare = {
    Primary =  "1.1.1.1",
    Secondary =  "1.0.0.1",
    Primary6 =  "2606:4700:4700::1111",
    Secondary6 =  "2606:4700:4700::1001"
}
Cloudflare_Malware = {
    Primary =  "1.1.1.2",
    Secondary =  "1.0.0.2",
    Primary6 =  "2606:4700:4700::1112",
    Secondary6 =  "2606:4700:4700::1002"
}
Cloudflare_Malware_Adult = {
    Primary =  "1.1.1.3",
    Secondary =  "1.0.0.3",
    Primary6 =  "2606:4700:4700::1113",
    Secondary6 =  "2606:4700:4700::1003"
}
Open_DNS = {
    Primary =  "208.67.222.222",
    Secondary =  "208.67.220.220",
    Primary6 =  "2620:119:35::35",
    Secondary6 =  "2620:119:53::53"
}
Quad9 = {
    Primary =  "9.9.9.9",
    Secondary =  "149.112.112.112",
    Primary6 =  "2620:fe::fe",
    Secondary6 =  "2620:fe::9"
}
AdGuard_Ads_Trackers = {
    Primary =  "94.140.14.14",
    Secondary =  "94.140.15.15",
    Primary6 =  "2a10:50c0::ad1:ff",
    Secondary6 =  "2a10:50c0::ad2:ff"
}
AdGuard_Ads_Trackers_Malware_Adult = {
    Primary =  "94.140.14.15",
    Secondary =  "94.140.15.16",
    Primary6 =  "2a10:50c0::bad1:ff",
    Secondary6 =  "2a10:50c0::bad2:ff"
}
  }
)
$f = @(
)
