function Set-WinUtilRegistry {
    <#

    .SYNOPSIS
        Modifies the registry based on the given inputs

    .PARAMETER Name
        The name of the key to modify

    .PARAMETER Path
        The path to the key

    .PARAMETER Type
        The type of value to set the key to

    .PARAMETER Value
        The value to set the key to

    .EXAMPLE
        Set-WinUtilRegistry -Name "PublishUserActivities" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Type "DWord" -Value "0"

    #>
    param (
        $Name,
        $Path,
        $Type,
        $Value
    )

    Try{
        if(!(Test-Path 'HKU:\')){New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS}

        If (!(Test-Path $Path)) {
            Write-Host "$Path was not found, Creating..."
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        Write-Host "Set $Path\$Name to $Value"
        Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force -ErrorAction Stop | Out-Null
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
# Like tiling windows
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
Function Set-WinUtilService {
    <#

    .SYNOPSIS
        Changes the startup type of the given service

    .PARAMETER Name
        The name of the service to modify

    .PARAMETER StartupType
        The startup type to set the service to

    .EXAMPLE
        Set-WinUtilService -Name "HomeGroupListener" -StartupType "Manual"

    #>
    param (
        $Name,
        $StartupType
    )
    try {
        Write-Host "Setting Service $Name to $StartupType"

        # Check if the service exists
        $service = Get-Service -Name $Name -ErrorAction Stop

        # Service exists, proceed with changing properties
        $service | Set-Service -StartupType $StartupType -ErrorAction Stop
    }
    catch [System.ServiceProcess.ServiceNotFoundException] {
        Write-Warning "Service $Name was not found"
    }
    catch {
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $_.Exception.Message
    }

}
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

    Write-Host "Resetting Network with netsh"

    # Reset WinSock catalog to a clean state
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    # Resets WinHTTP proxy setting to DIRECT
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    # Removes all user configured IP settings
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"

    Write-Host "Process complete. Please reboot your computer."

    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Network Reset "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information

    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "=========================================="
    Write-Host "-- Network Configuration has been Reset --"
    Write-Host "=========================================="
}
function Invoke-WPFFixesUpdate {

    <#

    .SYNOPSIS
        Performs various tasks in an attempt to repair Windows Update

    .DESCRIPTION
        1. (Aggressive Only) Scans the system for corruption using chkdsk, SFC, and DISM
            Steps:
                1. Runs chkdsk /scan /perf
                    /scan - Runs an online scan on the volume
                    /perf - Uses more system resources to complete a scan as fast as possible
                2. Runs SFC /scannow
                    /scannow - Scans integrity of all protected system files and repairs files with problems when possible
                3. Runs DISM /Online /Cleanup-Image /RestoreHealth
                    /Online - Targets the running operating system
                    /Cleanup-Image - Performs cleanup and recovery operations on the image
                    /RestoreHealth - Scans the image for component store corruption and attempts to repair the corruption using Windows Update
                4. Runs SFC /scannow
                    Ran twice in case DISM repaired SFC
        2. Stops Windows Update Services
        3. Remove the QMGR Data file, which stores BITS jobs
        4. (Aggressive Only) Renames the DataStore and CatRoot2 folders
            DataStore - Contains the Windows Update History and Log Files
            CatRoot2 - Contains the Signatures for Windows Update Packages
        5. Renames the Windows Update Download Folder
        6. Deletes the Windows Update Log
        7. (Aggressive Only) Resets the Security Descriptors on the Windows Update Services
        8. Reregisters the BITS and Windows Update DLLs
        9. Removes the WSUS client settings
        10. Resets WinSock
        11. Gets and deletes all BITS jobs
        12. Sets the startup type of the Windows Update Services then starts them
        13. Forces Windows Update to check for updates

    .PARAMETER Aggressive
        If specified, the script will take additional steps to repair Windows Update that are more dangerous, take a significant amount of time, or are generally unnecessary

    #>

    param($Aggressive = $false)

    Write-Progress -Id 0 -Activity "Repairing Windows Update" -PercentComplete 0
    # Wait for the first progress bar to show, otherwise the second one won't show
    Start-Sleep -Milliseconds 200

    if ($Aggressive) {
        # Scan system for corruption
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Scanning for corruption..." -PercentComplete 0
        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running chkdsk..." -PercentComplete 0
        # 2>&1 redirects stdout, alowing iteration over the output
        chkdsk.exe /scan /perf 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Get the index of the total percentage
            $index = $_.IndexOf("Total:")
            if (
                # If the percent is found
                ($percent = try {(
                    $_.Substring(
                        $index + 6,
                        $_.IndexOf("%", $index) - $index - 6
                    )
                ).Trim()} catch {0}) `
                <# And the current percentage is greater than the previous one #>`
                -and $percent -gt $oldpercent
            ){
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running chkdsk... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC..." -PercentComplete 0
        $oldpercent = 0
        # SFC has a bug when redirected which causes it to output only when the stdout buffer is full, causing the progress bar to move in chunks
        sfc /scannow 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                (
                    # Use a different method to get the percentage that accounts for SFC's Unicode output
                    [int]$percent = try {(
                        (
                            $_.Substring(
                                $_.IndexOf("n") + 2,
                                $_.IndexOf("%") - $_.IndexOf("n") - 2
                            ).ToCharArray() | Where-Object {$_}
                        ) -join ''
                    ).TrimStart()} catch {0}
                ) -and $percent -gt $oldpercent
            ){
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running DISM..." -PercentComplete 0
        $oldpercent = 0
        DISM /Online /Cleanup-Image /RestoreHealth | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                ($percent = try {
                    [int]($_ -replace "\[" -replace "=" -replace " " -replace "%" -replace "\]")
                } catch {0}) `
                -and $percent -gt $oldpercent
            ){
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running DISM... ($percent%)" -PercentComplete $percent
            }
        }

        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC again..." -PercentComplete 0
        $oldpercent = 0
        sfc /scannow 2>&1 | ForEach-Object {
            # Write stdout to the Verbose stream
            Write-Verbose $_

            # Filter for lines that contain a percentage that is greater than the previous one
            if (
                (
                    [int]$percent = try {(
                        (
                            $_.Substring(
                                $_.IndexOf("n") + 2,
                                $_.IndexOf("%") - $_.IndexOf("n") - 2
                            ).ToCharArray() | Where-Object {$_}
                        ) -join ''
                    ).TrimStart()} catch {0}
                ) -and $percent -gt $oldpercent
            ){
                # Update the progress bar
                $oldpercent = $percent
                Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Running SFC... ($percent%)" -PercentComplete $percent
            }
        }
        Write-Progress -Id 1 -ParentId 0 -Activity "Scanning for corruption" -Status "Completed" -PercentComplete 100
    }


    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Stopping Windows Update Services..." -PercentComplete 10
    # Stop the Windows Update Services
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping BITS..." -PercentComplete 0
    Stop-Service -Name BITS -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping wuauserv..." -PercentComplete 20
    Stop-Service -Name wuauserv -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping appidsvc..." -PercentComplete 40
    Stop-Service -Name appidsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping cryptsvc..." -PercentComplete 60
    Stop-Service -Name cryptsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Completed" -PercentComplete 100


    # Remove the QMGR Data file
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Renaming/Removing Files..." -PercentComplete 20
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing QMGR Data files..." -PercentComplete 0
    Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue


    if ($Aggressive) {
        # Rename the Windows Update Log and Signature Folders
        Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Log, Download, and Signature Folder..." -PercentComplete 20
        Rename-Item $env:systemroot\SoftwareDistribution\DataStore DataStore.bak -ErrorAction SilentlyContinue
        Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue
    }

    # Rename the Windows Update Download Folder
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Download Folder..." -PercentComplete 20
    Rename-Item $env:systemroot\SoftwareDistribution\Download Download.bak -ErrorAction SilentlyContinue

    # Delete the legacy Windows Update Log
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing the old Windows Update log..." -PercentComplete 80
    Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Completed" -PercentComplete 100


    if ($Aggressive) {
        # Reset the Security Descriptors on the Windows Update Services
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting the WU Service Security Descriptors..." -PercentComplete 25
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the BITS Security Descriptor..." -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "bits", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the wuauserv Security Descriptor..." -PercentComplete 50
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "wuauserv", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Completed" -PercentComplete 100
    }


    # Reregister the BITS and Windows Update DLLs
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Reregistering DLLs..." -PercentComplete 40
    $oldLocation = Get-Location
    Set-Location $env:systemroot\system32
    $i = 0
    $DLLs = @(
        "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
        "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
        "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
        "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
        "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
        "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
        "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
    )
    foreach ($dll in $DLLs) {
        Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Registering $dll..." -PercentComplete ($i / $DLLs.Count * 100)
        $i++
        Start-Process -NoNewWindow -FilePath "regsvr32.exe" -ArgumentList "/s", $dll
    }
    Set-Location $oldLocation
    Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Completed" -PercentComplete 100


    # Remove the WSUS client settings
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate") {
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Removing WSUS client settings..." -PercentComplete 60
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "AccountDomainSid", "/f" -RedirectStandardError $true
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "PingID", "/f" -RedirectStandardError $true
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "SusClientId", "/f" -RedirectStandardError $true
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -Status "Completed" -PercentComplete 100
    }


    # Reset WinSock
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting WinSock..." -PercentComplete 65
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Resetting WinSock..." -PercentComplete 0
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset" -RedirectStandardOutput $true
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy" -RedirectStandardOutput $true
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset" -RedirectStandardOutput $true
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Completed" -PercentComplete 100


    # Get and delete all BITS jobs
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Deleting BITS jobs..." -PercentComplete 75
    Write-Progress -Id 8 -ParentId 0 -Activity "Deleting BITS jobs" -Status "Deleting BITS jobs..." -PercentComplete 0
    Get-BitsTransfer | Remove-BitsTransfer
    Write-Progress -Id 8 -ParentId 0 -Activity "Deleting BITS jobs" -Status "Completed" -PercentComplete 100


    # Change the startup type of the Windows Update Services and start them
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Starting Windows Update Services..." -PercentComplete 90
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting BITS..." -PercentComplete 0
    Get-Service BITS | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting wuauserv..." -PercentComplete 25
    Get-Service wuauserv | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting AppIDSvc..." -PercentComplete 50
    # The AppIDSvc service is protected, so the startup type has to be changed in the registry
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value "3" # Manual
    Start-Service AppIDSvc
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting CryptSvc..." -PercentComplete 75
    Get-Service CryptSvc | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Completed" -PercentComplete 100


    # Force Windows Update to check for updates
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Forcing discovery..." -PercentComplete 95
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Forcing discovery..." -PercentComplete 0
    (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    Start-Process -NoNewWindow -FilePath "wuauclt" -ArgumentList "/resetauthorization", "/detectnow"
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Completed" -PercentComplete 100
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Completed" -PercentComplete 100

    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Reset Windows Update "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information

    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "==============================================="
    Write-Host "-- Reset All Windows Update Settings to Stock -"
    Write-Host "==============================================="

    # Remove the progress bars
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Completed
    Write-Progress -Id 1 -Activity "Scanning for corruption" -Completed
    Write-Progress -Id 2 -Activity "Stopping Services" -Completed
    Write-Progress -Id 3 -Activity "Renaming/Removing Files" -Completed
    Write-Progress -Id 4 -Activity "Resetting the WU Service Security Descriptors" -Completed
    Write-Progress -Id 5 -Activity "Reregistering DLLs" -Completed
    Write-Progress -Id 6 -Activity "Removing WSUS client settings" -Completed
    Write-Progress -Id 7 -Activity "Resetting WinSock" -Completed
    Write-Progress -Id 8 -Activity "Deleting BITS jobs" -Completed
    Write-Progress -Id 9 -Activity "Starting Windows Update Services" -Completed
    Write-Progress -Id 10 -Activity "Forcing discovery" -Completed
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
function Invoke-WPFUpdatesdefault {
    <#

    .SYNOPSIS
        Resets Windows Update settings to default

    #>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 3
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

    $services = @(
        "BITS"
        "wuauserv"
    )

    foreach ($service in $services) {
        # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

        Write-Host "Setting $service StartupType to Automatic"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
    }
    Write-Host "Enabling driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Enabling Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Write-Host "Enabled driver offering through Windows Update"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Write-Host "==================================================="
    Write-Host "---  Windows Update Settings Reset to Default   ---"
    Write-Host "==================================================="
}
function Invoke-WPFUpdatesdisable {
    <#

    .SYNOPSIS
        Disables Windows Update

    .NOTES
        Disabling Windows Update is not recommended. This is only for advanced users who know what they are doing.

    #>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0

    $services = @(
        "BITS"
        "wuauserv"
    )

    foreach ($service in $services) {
        # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

        Write-Host "Setting $service StartupType to Disabled"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
    }
    Write-Host "================================="
    Write-Host "---   Updates ARE DISABLED    ---"
    Write-Host "================================="
}
function Invoke-WPFUpdatessecurity {
    <#

    .SYNOPSIS
        Sets Windows Update to recommended settings

    .DESCRIPTION
        1. Disables driver offering through Windows Update
        2. Disables Windows Update automatic restart
        3. Sets Windows Update to Semi-Annual Channel (Targeted)
        4. Defers feature updates for 365 days
        5. Defers quality updates for 4 days

    #>
    Write-Host "Disabling driver offering through Windows Update..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
        Write-Host "Disabling Windows Update automatic restart..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
        Write-Host "Disabled driver offering through Windows Update"
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4

        $ButtonType = [System.Windows.MessageBoxButton]::OK
        $MessageboxTitle = "Set Security Updates"
        $Messageboxbody = ("Recommended Update settings loaded")
        $MessageIcon = [System.Windows.MessageBoxImage]::Information

        [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
        Write-Host "================================="
        Write-Host "-- Updates Set to Recommended ---"
        Write-Host "================================="
}
function Get-WinUtilWingetLatest {
    <#
    .SYNOPSIS
        Uses GitHub API to check for the latest release of Winget.
    .DESCRIPTION
        This function grabs the latest version of Winget and returns the download path to Install-WinUtilWinget for installation.
    #>
    # Invoke-WebRequest is notoriously slow when the byte progress is displayed. The following lines disable the progress bar and reset them at the end of the function
    $PreviousProgressPreference = $ProgressPreference
    $ProgressPreference = "silentlyContinue"
    Try{
        # Grabs the latest release of Winget from the Github API for the install process.
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/Winget-cli/releases/latest" -Method Get -ErrorAction Stop
        $latestVersion = $response.tag_name #Stores version number of latest release.
        $licenseWingetUrl = $response.assets.browser_download_url | Where-Object {$_ -like "*License1.xml"} #Index value for License file.
        Write-Host "Latest Version:`t$($latestVersion)`n"
        Write-Host "Downloading..."
        $assetUrl = $response.assets.browser_download_url | Where-Object {$_ -like "*Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"}
        Invoke-WebRequest -Uri $licenseWingetUrl -OutFile $ENV:TEMP\License1.xml
        # The only pain is that the msixbundle for winget-cli is 246MB. In some situations this can take a bit, with slower connections.
        Invoke-WebRequest -Uri $assetUrl -OutFile $ENV:TEMP\Microsoft.DesktopAppInstaller.msixbundle
    }
    Catch{
        throw [WingetFailedInstall]::new('Failed to get latest Winget release and license')
    }
    $ProgressPreference = $PreviousProgressPreference
}
function Get-WinUtilWingetPrerequisites {
    <#
    .SYNOPSIS
        Downloads the Winget Prereqs.
    .DESCRIPTION
        Downloads Prereqs for Winget. Version numbers are coded as variables and can be updated as uncommonly as Microsoft updates the prereqs.
    #>

    # I don't know of a way to detect the prereqs automatically, so if someone has a better way of defining these, that would be great.
    # Microsoft.VCLibs version rarely changes, but for future compatibility I made it a variable.
    $versionVCLibs = "14.00"
    $fileVCLibs = "https://aka.ms/Microsoft.VCLibs.x64.${versionVCLibs}.Desktop.appx"
    # Write-Host "$fileVCLibs"
    # Microsoft.UI.Xaml version changed recently, so I made the version numbers variables.
    $versionUIXamlMinor = "2.8"
    $versionUIXamlPatch = "2.8.6"
    $fileUIXaml = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v${versionUIXamlPatch}/Microsoft.UI.Xaml.${versionUIXamlMinor}.x64.appx"
    # Write-Host "$fileUIXaml"

    Try{
        Write-Host "Downloading Microsoft.VCLibs Dependency..."
        Invoke-WebRequest -Uri $fileVCLibs -OutFile $ENV:TEMP\Microsoft.VCLibs.x64.Desktop.appx
        Write-Host "Downloading Microsoft.UI.Xaml Dependency...`n"
        Invoke-WebRequest -Uri $fileUIXaml -OutFile $ENV:TEMP\Microsoft.UI.Xaml.x64.appx
    }
    Catch{
        throw [WingetFailedInstall]::new('Failed to install prerequsites')
    }
}
function Install-WinUtilWinget {
    <#

    .SYNOPSIS
        Installs Winget if it is not already installed.

    .DESCRIPTION
        This function will download the latest version of Winget and install it. If Winget is already installed, it will do nothing.
    #>
    $isWingetInstalled = Test-WinUtilPackageManager -winget

    Try {
        if ($isWingetInstalled -eq "installed") {
            Write-Host "`nWinget is already installed.`r" -ForegroundColor Green
            return
        } elseif ($isWingetInstalled -eq "outdated") {
            Write-Host "`nWinget is Outdated. Continuing with install.`r" -ForegroundColor Yellow
        } else {
            Write-Host "`nWinget is not Installed. Continuing with install.`r" -ForegroundColor Red
        }

        # Gets the computer's information
        if ($null -eq $sync.ComputerInfo){
            $ComputerInfo = Get-ComputerInfo -ErrorAction Stop
        } else {
            $ComputerInfo = $sync.ComputerInfo
        }

        if (($ComputerInfo.WindowsVersion) -lt "1809") {
            # Checks if Windows Version is too old for Winget
            Write-Host "Winget is not supported on this version of Windows (Pre-1809)" -ForegroundColor Red
            return
        }

        # Install Winget via GitHub method.
        # Used part of my own script with some modification: ruxunderscore/windows-initialization
        Write-Host "Downloading Winget Prerequsites`n"
        Get-WinUtilWingetPrerequisites
        Write-Host "Downloading Winget and License File`r"
        Get-WinUtilWingetLatest
        Write-Host "Installing Winget w/ Prerequsites`r"
        Add-AppxProvisionedPackage -Online -PackagePath $ENV:TEMP\Microsoft.DesktopAppInstaller.msixbundle -DependencyPackagePath $ENV:TEMP\Microsoft.VCLibs.x64.Desktop.appx, $ENV:TEMP\Microsoft.UI.Xaml.x64.appx -LicensePath $ENV:TEMP\License1.xml
		Write-Host "Manually adding Winget Sources, from Winget CDN."
		Add-AppxPackage -Path https://cdn.winget.microsoft.com/cache/source.msix #Seems some installs of Winget don't add the repo source, this should makes sure that it's installed every time.
        Write-Host "Winget Installed" -ForegroundColor Green
        Write-Host "Enabling NuGet and Module..."
        Install-PackageProvider -Name NuGet -Force
        Install-Module -Name Microsoft.WinGet.Client -Force
        # Winget only needs a refresh of the environment variables to be used.
        Write-Output "Refreshing Environment Variables...`n"
        $ENV:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    } Catch {
        Write-Host "Failure detected while installing via GitHub method. Continuing with Chocolatey method as fallback." -ForegroundColor Red
        # In case install fails via GitHub method.
        Try {
        # Install Choco if not already present
        Install-WinUtilChoco
        Start-Process -Verb runas -FilePath powershell.exe -ArgumentList "choco install winget-cli"
        Write-Host "Winget Installed" -ForegroundColor Green
        Write-Output "Refreshing Environment Variables...`n"
        $ENV:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        } Catch {
            throw [WingetFailedInstall]::new('Failed to install!')
        }
    }
}
Function Install-WinUtilProgramWinget {

    <#
    .SYNOPSIS
    Manages the provided programs using Winget

    .PARAMETER ProgramsToInstall
    A list of programs to manage

    .PARAMETER manage
    The action to perform on the programs, can be either 'Installing' or 'Uninstalling'

    .NOTES
    The triple quotes are required any time you need a " in a normal script block.
    The winget Return codes are documented here: https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md
    #>

    param(
        [Parameter(Mandatory, Position=0)]
        [PsCustomObject]$ProgramsToInstall,

        [Parameter(Position=1)]
        [String]$manage = "Installing"
    )
    $x = 0
    $count = $ProgramsToInstall.Count

    Write-Progress -Activity "$manage Applications" -Status "Starting" -PercentComplete 0
    Write-Host "==========================================="
    Write-Host "--    Configuring winget packages       ---"
    Write-Host "==========================================="
    Foreach ($Program in $ProgramsToInstall){
        $failedPackages = @()
        Write-Progress -Activity "$manage Applications" -Status "$manage $($Program.winget) $($x + 1) of $count" -PercentComplete $($x/$count*100)
        if($manage -eq "Installing"){
            # Install package via ID, if it fails try again with different scope and then with an unelevated prompt.
            # Since Install-WinGetPackage might not be directly available, we use winget install command as a workaround.
            # Winget, not all installers honor any of the following: System-wide, User Installs, or Unelevated Prompt OR Silent Install Mode.
            # This is up to the individual package maintainers to enable these options. Aka. not as clean as Linux Package Managers.
            Write-Host "Starting install of $($Program.winget) with winget."
            try {
                $status = $(Start-Process -FilePath "winget" -ArgumentList "install --id $($Program.winget) --silent --accept-source-agreements --accept-package-agreements" -Wait -PassThru -NoNewWindow).ExitCode
                if($status -eq 0){
                    Write-Host "$($Program.winget) installed successfully."
                    continue
                }
                if ($status -eq  -1978335189){
                    Write-Host "$($Program.winget) No applicable update found"
                    continue
                }
                Write-Host "Attempt with User scope"
                $status = $(Start-Process -FilePath "winget" -ArgumentList "install --id $($Program.winget) --scope user --silent --accept-source-agreements --accept-package-agreements" -Wait -PassThru -NoNewWindow).ExitCode
                if($status -eq 0){
                    Write-Host "$($Program.winget) installed successfully with User scope."
                    continue
                }
                if ($status -eq  -1978335189){
                    Write-Host "$($Program.winget) No applicable update found"
                    continue
                }
                Write-Host "Attempt with User prompt"
                $userChoice = [System.Windows.MessageBox]::Show("Do you want to attempt $($Program.winget) installation with specific user credentials? Select 'Yes' to proceed or 'No' to skip.", "User Credential Prompt", [System.Windows.MessageBoxButton]::YesNo)
                if ($userChoice -eq 'Yes') {
                    $getcreds = Get-Credential
                    $process = Start-Process -FilePath "winget" -ArgumentList "install --id $($Program.winget) --silent --accept-source-agreements --accept-package-agreements" -Credential $getcreds -PassThru -NoNewWindow
                    Wait-Process -Id $process.Id
                    $status = $process.ExitCode
                } else {
                    Write-Host "Skipping installation with specific user credentials."
                }
                if($status -eq 0){
                    Write-Host "$($Program.winget) installed successfully with User prompt."
                    continue
                }
                if ($status -eq  -1978335189){
                    Write-Host "$($Program.winget) No applicable update found"
                    continue
                }
            } catch {
                Write-Host "Failed to install $($Program.winget). With winget"
                $failedPackages += $Program
            }
        }
        if($manage -eq "Uninstalling"){
            # Uninstall package via ID using winget directly.
            try {
                $status = $(Start-Process -FilePath "winget" -ArgumentList "uninstall --id $($Program.winget) --silent" -Wait -PassThru -NoNewWindow).ExitCode
                if($status -ne 0){
                    Write-Host "Failed to uninstall $($Program.winget)."
                } else {
                    Write-Host "$($Program.winget) uninstalled successfully."
                    $failedPackages += $Program
                }
            } catch {
                Write-Host "Failed to uninstall $($Program.winget) due to an error: $_"
                $failedPackages += $Program
            }
        }
        $X++
    }
    Write-Progress -Activity "$manage Applications" -Status "Finished" -Completed
    return $failedPackages;
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



$a = @("Content": "Set Display for Performance",
    "Description": "Sets the system preferences to performance. You can do this manually with sysdm.cpl as well.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "DragFullWindows",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "MenuShowDelay",
        "Value": "200",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop\\WindowMetrics",
        "OriginalValue": "1",
        "Name": "MinAnimate",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "OriginalValue": "1",
        "Name": "KeyboardDelay",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewAlphaSelect",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewShadow",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarAnimations",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
        "OriginalValue": "1",
        "Name": "VisualFXSetting",
        "Value": "3",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\DWM",
        "OriginalValue": "1",
        "Name": "EnableAeroPeek",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarMn",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarDa",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "OriginalValue": "1",
        "Name": "SearchboxTaskbarMode",
        "Value": "0",
        "Type": "DWord"
      }
    ]
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
    ]
    "UndoScript": [
      "Remove-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\""
    ]
)
$b = @("Content": "Remove ALL MS Store Apps - NOT RECOMMENDED",
    "Description": "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a028_",
    "appx": [
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
    "InvokeScript": [
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
$c = @("Content": "Set Time to UTC (Dual Boot)",
    "Description": "Essential for computers that are dual booting. Fixes the time sync with Linux Systems.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "Name": "RealTimeIsUniversal",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      }
    ]
)
$d = @("Content": "Disable Wifi-Sense",
    "Description": "Wifi Sense is a spying service that phones home all nearby scanned wifi networks and your current geo location.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting",
        "Name": "Value",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots",
        "Name": "Value",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
)
$e = @("Content": "Disable ConsumerFeatures",
    "Description": "Windows 10 will not automatically install any games, third-party apps, or application links from the Windows Store for the signed-in user. Some default Apps will be inaccessible (eg. Phone Link)",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a003_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "OriginalValue": "0",
        "Name": "DisableWindowsConsumerFeatures",
        "Value": "1",
        "Type": "DWord"
      }
    ]
)
$f = @("Content": "Disable Telemetry",
    "Description": "Disables Microsoft Telemetry. Note: This will lock many Edge Browser settings. Microsoft spies heavily on you when using the Edge browser.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a003_",
    "ScheduledTask": [
      {
        "Name": "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Autochk\\Proxy",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\MareBackup",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\StartupAppTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      },
      {
        "Name": "Microsoft\\Windows\\Maps\\MapsUpdateTask",
        "State": "Disabled",
        "OriginalState": "Enabled"
      }
    ],
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
        "Type": "DWord",
        "Value": "0",
        "Name": "AllowTelemetry",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "OriginalValue": "1",
        "Name": "AllowTelemetry",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "ContentDeliveryAllowed",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "OemPreInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "PreInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "PreInstalledAppsEverEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SilentInstalledAppsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338387Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338388Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-338389Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SubscribedContent-353698Enabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
        "OriginalValue": "1",
        "Name": "SystemPaneSuggestionsEnabled",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Siuf\\Rules",
        "OriginalValue": "0",
        "Name": "NumberOfSIUFInPeriod",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
        "OriginalValue": "0",
        "Name": "DoNotShowFeedbackNotifications",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
        "OriginalValue": "0",
        "Name": "DisableTailoredExperiencesWithDiagnosticData",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo",
        "OriginalValue": "0",
        "Name": "DisabledByGroupPolicy",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting",
        "OriginalValue": "0",
        "Name": "Disabled",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config",
        "OriginalValue": "1",
        "Name": "DODownloadMode",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance",
        "OriginalValue": "1",
        "Name": "fAllowToGetHelp",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\OperationStatusManager",
        "OriginalValue": "0",
        "Name": "EnthusiastMode",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
        "OriginalValue": "1",
        "Name": "PeopleBand",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "LaunchTo",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
        "OriginalValue": "0",
        "Name": "LongPathsEnabled",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "_Comment": "Driver searching is a function that should be left in",
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching",
        "OriginalValue": "1",
        "Name": "SearchOrderConfig",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "OriginalValue": "1",
        "Name": "SystemResponsiveness",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        "OriginalValue": "1",
        "Name": "NetworkThrottlingIndex",
        "Value": "4294967295",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "MenuShowDelay",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "AutoEndTasks",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "OriginalValue": "0",
        "Name": "ClearPageFileAtShutdown",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\ControlSet001\\Services\\Ndu",
        "OriginalValue": "1",
        "Name": "Start",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Control Panel\\Mouse",
        "OriginalValue": "400",
        "Name": "MouseHoverTime",
        "Value": "400",
        "Type": "String"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "OriginalValue": "20",
        "Name": "IRPStackSize",
        "Value": "30",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds",
        "OriginalValue": "1",
        "Name": "EnableFeeds",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Feeds",
        "OriginalValue": "1",
        "Name": "ShellFeedsTaskbarViewMode",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "OriginalValue": "1",
        "Name": "HideSCAMeetNow",
        "Value": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement",
        "OriginalValue": "1",
        "Name": "ScoobeSystemSettingEnabled",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
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
$f = @("Content": "Set Services to Manual",
    "Description": "Turns a bunch of system services to manual that don&#39;t need to be running all the time. This is pretty harmless as if the service is needed, it will simply start on demand.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a014_",
    "service": [
      {
        "Name": "AJRouter",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "ALG",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppIDSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppMgmt",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppReadiness",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AppVClient",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "AppXSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Appinfo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "AssignedAccessManagerSvc",
        "StartupType": "Disabled",
        "OriginalType": "Manual"
      },
      {
        "Name": "AudioEndpointBuilder",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AudioSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Audiosrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AxInstSV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BDESVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BFE",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BITS",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BTAGService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BcastDVRUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BluetoothUserService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BrokerInfrastructure",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Browser",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "BthAvctpSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "BthHFSrv",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CDPUserSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "COMSysApp",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CaptureService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CertPropSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ClipSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ConsentUxUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CoreMessagingRegistrar",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CredentialEnrollmentManagerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "CryptSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CscService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DPS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcomLaunch",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DcpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevQueryBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationBrokerSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceAssociationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DeviceInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicePickerUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DevicesFlowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dhcp",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DiagTrack",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DialogBlockingService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "DispBrokerDesktopSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DisplayEnhancementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DmEnrollmentSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Dnscache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DoSvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "DsSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DsmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "DusmSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EFS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EapHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EntAppSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "EventLog",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "EventSystem",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FDResPub",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Fax",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FontCache",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "FrameServer",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "FrameServerMonitor",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "GraphicsPerfSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupListener",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HomeGroupProvider",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "HvHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IEEtwCollectorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IKEEXT",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InstallService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "InventorySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "IpxlatCfgSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "KeyIso",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "KtmRm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LSM",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanServer",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LanmanWorkstation",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "LicenseManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "LxpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSDTC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MSiSCSI",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MapsBroker",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "McpManagementService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MessagingService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MicrosoftEdgeElevationService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MixedRealityOpenXRSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "MpsSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "MsKeyboardFilter",
        "StartupType": "Manual",
        "OriginalType": "Disabled"
      },
      {
        "Name": "NPSMSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NaturalAuthentication",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcbService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NcdAutoSetup",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetSetupSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NetTcpPortSharing",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "Netlogon",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Netman",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcCtnrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NgcSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "NlaSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "OneSyncSvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "P9RdrService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPAutoReg",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PNRPsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PcaSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PeerDistSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PenService_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PerfHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PhoneSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PimIndexMaintenanceSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PlugPlay",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PolicyAgent",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Power",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PrintNotify",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "PrintWorkflowUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ProfSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "PushToInstall",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "QWAVE",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasAuto",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RasMan",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RemoteAccess",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RemoteRegistry",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "RetailDemo",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RmSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcEptMapper",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "RpcLocator",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "RpcSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SCPolicySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SCardSvr",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SDRSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SEMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SENS",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SNMPTRAP",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SNMPTrap",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SSDPSRV",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SamSs",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ScDeviceEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Schedule",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SecurityHealthService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Sense",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorDataService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensorService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SensrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SessionEnv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SgrmBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SharedAccess",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "SharedRealitySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "ShellHWDetection",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SmsRouter",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Spooler",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SstpSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StateRepository",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "StiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "StorSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SysMain",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "SystemEventsBroker",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TabletInputService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TapiSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TermService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TextInputManagementService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Themes",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TieringEngineService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TimeBrokerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TokenBroker",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrkWks",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "TroubleshootingSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "TrustedInstaller",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UI0Detect",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UdkUserSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UevAgentService",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "UmRdpService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UnistoreSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserDataSvc_*",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "UserManager",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "UsoSvc",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VGAuthService",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VMTools",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "VSS",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VacSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "VaultSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "W32Time",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WEPHOSTSVC",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WFDSConMgrSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WMPNetworkSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WManSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WPDBusEnum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WSearch",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WaaSMedicSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WalletService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WarpJITSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WbioSrvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wcmsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WcsPlugInService",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdNisSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiServiceHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WdiSystemHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WebClient",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Wecsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WerSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WiaRpc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinDefend",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WinHttpAutoProxySvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WinRM",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "Winmgmt",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WlanSvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpcMonSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "WpnService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "WpnUserService_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "XblAuthManager",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XblGameSave",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxGipSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "XboxNetApiSvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "autotimesvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "bthserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "camsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "cbdhsvc_*",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "cloudidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dcsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "defragsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagnosticshub.standardcollector.service",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "diagsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dmwappushservice",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "dot3svc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "edgeupdate",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "edgeupdatem",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "embeddedmode",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fdPHost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "fhsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "gpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "hidserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "icssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "iphlpsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "lfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lltdsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "lmhosts",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "mpssvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "msiserver",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "netprofm",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "nsi",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "p2pimsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "p2psvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "perceptionsimulation",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "pla",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "seclogon",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "shpamsvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "smphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "spectrum",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "sppsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "ssh-agent",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "svsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "swprv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "tiledatamodelsvc",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "tzautoupdate",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "uhssvc",
        "StartupType": "Disabled",
        "OriginalType": "Disabled"
      },
      {
        "Name": "upnphost",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vds",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vm3dservice",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "vmicguestinterface",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicheartbeat",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmickvpexchange",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicrdv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicshutdown",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmictimesync",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvmsession",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmicvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "vmvss",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wbengine",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wcncsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "webthreatdefusersvc_*",
        "StartupType": "Automatic",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wercplsupport",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wisvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlidsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wlpasvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wmiApSrv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "workfolderssvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wscsvc",
        "StartupType": "AutomaticDelayedStart",
        "OriginalType": "Automatic"
      },
      {
        "Name": "wuauserv",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      },
      {
        "Name": "wudfsvc",
        "StartupType": "Manual",
        "OriginalType": "Manual"
      }
    ]
)
$f = @("Content": "Disable Location Tracking",
    "Description": "Disables Location Tracking...DUH!",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location",
        "Name": "Value",
        "Type": "String",
        "Value": "Deny",
        "OriginalValue": "Allow"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Sensor\\Overrides\\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
        "Name": "SensorPermissionState",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration",
        "Name": "Status",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SYSTEM\\Maps",
        "Name": "AutoUpdateEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
)
$f = @("Content": "Disable Homegroup",
    "Description": "Disables HomeGroup - HomeGroup is a password-protected home networking service that lets you share your stuff with other PCs that are currently running and connected to your network.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "service": [
      {
        "Name": "HomeGroupListener",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "HomeGroupProvider",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      }
    ]
)
$f = @("Content": "Set Hibernation as default (good for laptops)",
    "Description": "Most modern laptops have connected stadby enabled which drains the battery, this sets hibernation as default which will not drain the battery. See issue https://github.com/ChrisTitusTech/winutil/issues/1399",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a014_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0",
        "OriginalValue": "1",
        "Name": "Attributes",
        "Value": "2",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab\\94ac6d29-73ce-41a6-809f-6363ba21b47e",
        "OriginalValue": "0",
        "Name": "Attributes ",
        "Value": "2",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
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
    "UndoScript": [
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
$f = @("Content": "Disable Hibernation",
    "Description": "Hibernation is really meant for laptops as it saves what&#39;s in memory before turning the pc off. It really should never be used, but some people are lazy and rely on it. Don&#39;t be like Bob. Bob likes hibernation.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Power",
        "Name": "HibernateEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings",
        "Name": "ShowHibernateOption",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "InvokeScript": [
      "powercfg.exe /hibernate off"
    ],
    "UndoScript": [
      "powercfg.exe /hibernate on"
    ]
)
$f = @("Content": "Disable Activity History",
    "Description": "This erases recent docs, clipboard, and run history.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "EnableActivityFeed",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "PublishUserActivities",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
        "Name": "UploadUserActivities",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
)
$f = @("Content": "NFS - Network File System",
    "Description": "Network File System (NFS) is a mechanism for storing files on a network.",
    "category": "Features",
    "panel": "1",
    "Order": "a014_",
    "feature": [
      "ServicesForNFS-ClientOnly",
      "ClientForNFS-Infrastructure",
      "NFS-Administration"
    ],
    "InvokeScript": [
      "nfsadmin client stop",
      "Set-ItemProperty -Path ''HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default'' -Name ''AnonymousUID'' -Type DWord -Value 0",
      "Set-ItemProperty -Path ''HKLM:\\SOFTWARE\\Microsoft\\ClientForNFS\\CurrentVersion\\Default'' -Name ''AnonymousGID'' -Type DWord -Value 0",
      "nfsadmin client start",
      "nfsadmin client localhost config fileaccess=755 SecFlavors=+sys -krb5 -krb5i"
    ]
)
$f = @("Content": "Enable/Disable Search Box Web Suggestions in Registry(explorer restart)",
    "Description": "Enables web suggestions when searching using Windows Search.",
    "category": "Features",
    "panel": "1",
    "Order": "a015_",
    "feature": [],
    "InvokeScript": [
      "
      If (!(Test-Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'')) {
            New-Item -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Name ''DisableSearchBoxSuggestions'' -Type DWord -Value 0 -Force
      Stop-Process -name explorer -force
      "
    ]
  
  



"Content": "Disable Search Box Web Suggestions in Registry(explorer restart)",
    "Description": "Disables web suggestions when searching using Windows Search.",
    "category": "Features",
    "panel": "1",
    "Order": "a016_",
    "feature": [],
    "InvokeScript": [
      "
      If (!(Test-Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'')) {
            New-Item -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'' -Name ''DisableSearchBoxSuggestions'' -Type DWord -Value 1 -Force
      Stop-Process -name explorer -force
      "
    ]
)
$f = @("Content": "Enable Daily Registry Backup Task 12.30am",
    "Description": "Enables daily registry backup, previously disabled by Microsoft in Windows 10 1803.",
    "category": "Features",
    "panel": "1",
    "Order": "a017_",
    "feature": [],
    "InvokeScript": [
      "
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager'' -Name ''EnablePeriodicBackup'' -Type DWord -Value 1 -Force
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager'' -Name ''BackupCount'' -Type DWord -Value 2 -Force
      $action = New-ScheduledTaskAction -Execute ''schtasks'' -Argument ''/run /i /tn \"\\Microsoft\\Windows\\Registry\\RegIdleBackup\"''
      $trigger = New-ScheduledTaskTrigger -Daily -At 00:30
      Register-ScheduledTask -Action $action -Trigger $trigger -TaskName ''AutoRegBackup'' -Description ''Create System Registry Backups'' -User ''System''
      "
    ]
)
$f = @("Content": "Enable\Disable Legacy F8 Boot Recovery",
    "Description": "Enables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    "category": "Features",
    "panel": "1",
    "Order": "a018_",
    "feature": [],
    "InvokeScript": [
      "
      If (!(Test-Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'')) {
            New-Item -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Name ''Enabled'' -Type DWord -Value 1 -Force
      Start-Process -FilePath cmd.exe -ArgumentList ''/c bcdedit /Set {Current} BootMenuPolicy Legacy'' -Wait
      "
    ]

"Content": "Disable Legacy F8 Boot Recovery",
    "Description": "Disables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes.",
    "category": "Features",
    "panel": "1",
    "Order": "a019_",
    "feature": [],
    "InvokeScript": [
      "
      If (!(Test-Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'')) {
            New-Item -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Force | Out-Null
      }
      New-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\\LastKnownGood'' -Name ''Enabled'' -Type DWord -Value 0 -Force
      Start-Process -FilePath cmd.exe -ArgumentList ''/c bcdedit /Set {Current} BootMenuPolicy Standard'' -Wait
      "
    ]
)
$f = @("Content": "Windows Sandbox",
    "category": "Features",
    "panel": "1",
    "Order": "a021_",
    "Description": "Windows Sandbox is a lightweight virtual machine that provides a temporary desktop environment to safely run applications and programs in isolation."
)
$f = @("Content": "Disable Teredo",
    "Description": "Teredo network tunneling is a ipv6 feature that can cause additional latency.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        "Name": "DisabledComponents",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "netsh interface teredo set state disabled"
    ],
    "UndoScript": [
      "netsh interface teredo set state default"
    ]
)
$f = @("Content": "Disable GameDVR",
    "Description": "GameDVR is a Windows App that is a dependency for some Store Games. I&#39;ve never met someone that likes it, but it&#39;s there for the XBOX crowd.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "registry": [
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_FSEBehavior",
        "Value": "2",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_Enabled",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_HonorUserFSEBehaviorMode",
        "Value": "1",
        "OriginalValue": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\System\\GameConfigStore",
        "Name": "GameDVR_EFSEFeatureFlags",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      },
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
        "Name": "AllowGameDVR",
        "Value": "0",
        "OriginalValue": "1",
        "Type": "DWord"
      }
    ]
)
$f = @("Content": "Delete Temporary Files",
    "Description": "Erases TEMP Folders",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a002_",
    "InvokeScript": [
      "Get-ChildItem -Path \"C:\\Windows\\Temp\" *.* -Recurse | Remove-Item -Force -Recurse
    Get-ChildItem -Path $env:TEMP *.* -Recurse | Remove-Item -Force -Recurse"
    ]
)
$f = @("Content": "Run Disk Cleanup",
    "Description": "Runs Disk Cleanup on Drive C: and removes old Windows Updates.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a009_",
    "InvokeScript": [
      "
      cleanmgr.exe /d C: /VERYLOWDISK
      Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
      "
    ]
)
$f = @("Content": "Set Classic Right-Click Menu ",
    "Description": "Great Windows 11 tweak to bring back good context menus when right clicking things in explorer.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "InvokeScript": [
      "
      New-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Name \"InprocServer32\" -force -value \"\"
      Write-Host Restarting explorer.exe ...
      $process = Get-Process -Name \"explorer\"
      Stop-Process -InputObject $process
      "
    ],
    "UndoScript": [
      "
      Remove-Item -Path \"HKCU:\\Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\" -Recurse -Confirm:$false -Force
      # Restarting Explorer in the Undo Script might not be necessary, as the Registry change without restarting Explorer does work, but just to make sure.
      Write-Host Restarting explorer.exe ...
      $process = Get-Process -Name \"explorer\"
      Stop-Process -InputObject $process
      "
    ]
)
$f = @("Content": "Adobe Debloat",
    "Description": "Manages Adobe Services, Adobe Desktop Service, and Acrobat Updates",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a021_",
    "InvokeScript": [
      "
      function CCStopper {
        $path = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe\"

        # Test if the path exists before proceeding
        if (Test-Path $path) {
            Takeown /f $path
            $acl = Get-Acl $path
            $acl.SetOwner([System.Security.Principal.NTAccount]\"Administrators\")
            $acl | Set-Acl $path

            Rename-Item -Path $path -NewName \"Adobe Desktop Service.exe.old\" -Force
        } else {
            Write-Host \"Adobe Desktop Service is not in the default location.\"
        }
      }


      function AcrobatUpdates {
        # Editing Acrobat Updates. The last folder before the key is dynamic, therefore using a script.
        # Possible Values for the edited key:
        # 0 = Do not download or install updates automatically
        # 2 = Automatically download updates but let the user choose when to install them
        # 3 = Automatically download and install updates (default value)
        # 4 = Notify the user when an update is available but don''t download or install it automatically
        #   = It notifies the user using Windows Notifications. It runs on startup without having to have a Service/Acrobat/Reader running, therefore 0 is the next best thing.

        $rootPath = \"HKLM:\\SOFTWARE\\WOW6432Node\\Adobe\\Adobe ARM\\Legacy\\Acrobat\"

        # Get all subkeys under the specified root path
        $subKeys = Get-ChildItem -Path $rootPath | Where-Object { $_.PSChildName -like \"{*}\" }

        # Loop through each subkey
        foreach ($subKey in $subKeys) {
            # Get the full registry path
            $fullPath = Join-Path -Path $rootPath -ChildPath $subKey.PSChildName
            try {
                Set-ItemProperty -Path $fullPath -Name Mode -Value 0
                Write-Host \"Acrobat Updates have been disabled.\"
            } catch {
                Write-Host \"Registry Key for changing Acrobat Updates does not exist in $fullPath\"
            }
        }
      }

      CCStopper
      AcrobatUpdates
      "
    ]
    "UndoScript": [
      "
      function RestoreCCService {
        $originalPath = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe.old\"
        $newPath = \"C:\\Program Files (x86)\\Common Files\\Adobe\\Adobe Desktop Common\\ADS\\Adobe Desktop Service.exe\"

        if (Test-Path -Path $originalPath) {
            Rename-Item -Path $originalPath -NewName \"Adobe Desktop Service.exe\" -Force
            Write-Host \"Adobe Desktop Service has been restored.\"
        } else {
            Write-Host \"Backup file does not exist. No changes were made.\"
        }
      }

      function AcrobatUpdates {
        # Default Value:
        # 3 = Automatically download and install updates

        $rootPath = \"HKLM:\\SOFTWARE\\WOW6432Node\\Adobe\\Adobe ARM\\Legacy\\Acrobat\"

        # Get all subkeys under the specified root path
        $subKeys = Get-ChildItem -Path $rootPath | Where-Object { $_.PSChildName -like \"{*}\" }

        # Loop through each subkey
        foreach ($subKey in $subKeys) {
            # Get the full registry path
            $fullPath = Join-Path -Path $rootPath -ChildPath $subKey.PSChildName
            try {
                Set-ItemProperty -Path $fullPath -Name Mode -Value 3
            } catch {
                Write-Host \"Registry Key for changing Acrobat Updates does not exist in $fullPath\"
            }
        }
      }

      RestoreCCService
      AcrobatUpdates
      "
    ]
    "service": [
      {
        "Name": "AGSService",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AGMService",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeUpdateService",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Acrobat Update",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Genuine Monitor Service",
        "StartupType": "Disabled",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeARMservice",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "Adobe Licensing Console",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CCXProcess",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "AdobeIPCBroker",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      },
      {
        "Name": "CoreSync",
        "StartupType": "Manual",
        "OriginalType": "Automatic"
      }
    ]
  
"Content": "Adobe Network Block",
    "Description": "Reduce user interruptions by selectively blocking connections to Adobe&#39;s activation and telemetry servers. Credit: Ruddernation-Designs",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a021_",
    "InvokeScript": [
      "
      # Define the URL of the remote HOSTS file and the local paths
      $remoteHostsUrl = \"https://raw.githubusercontent.com/Ruddernation-Designs/Adobe-URL-Block-List/master/hosts\"
      $localHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\hosts\"
      $tempHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\temp_hosts\"

      # Download the remote HOSTS file to a temporary location
      try {
          Invoke-WebRequest -Uri $remoteHostsUrl -OutFile $tempHostsPath
          Write-Output \"Downloaded the remote HOSTS file to a temporary location.\"
      }
      catch {
          Write-Error \"Failed to download the HOSTS file. Error: $_\"
      }

      # Check if the AdobeNetBlock has already been started
      try {
          $localHostsContent = Get-Content $localHostsPath -ErrorAction Stop

          # Check if AdobeNetBlock markers exist
          $blockStartExists = $localHostsContent -like \"*#AdobeNetBlock-start*\"
          if ($blockStartExists) {
              Write-Output \"AdobeNetBlock-start already exists. Skipping addition of new block.\"
          } else {
              # Load the new block from the downloaded file
              $newBlockContent = Get-Content $tempHostsPath -ErrorAction Stop
              $newBlockContent = $newBlockContent | Where-Object { $_ -notmatch \"^\\s*#\" -and $_ -ne \"\" } # Exclude empty lines and comments
              $newBlockHeader = \"#AdobeNetBlock-start\"
              $newBlockFooter = \"#AdobeNetBlock-end\"

              # Combine the contents, ensuring new block is properly formatted
              $combinedContent = $localHostsContent + $newBlockHeader, $newBlockContent, $newBlockFooter | Out-String

              # Write the combined content back to the original HOSTS file
              $combinedContent | Set-Content $localHostsPath -Encoding ASCII
              Write-Output \"Successfully added the AdobeNetBlock.\"
          }
      }
      catch {
          Write-Error \"Error during processing: $_\"
      }

      # Clean up temporary file
      Remove-Item $tempHostsPath -ErrorAction Ignore

      # Flush the DNS resolver cache
      try {
          Invoke-Expression \"ipconfig /flushdns\"
          Write-Output \"DNS cache flushed successfully.\"
      }
      catch {
          Write-Error \"Failed to flush DNS cache. Error: $_\"
      }
      "
    ]
    "UndoScript": [
      "
      # Define the local path of the HOSTS file
      $localHostsPath = \"C:\\Windows\\System32\\drivers\\etc\\hosts\"

      # Load the content of the HOSTS file
      try {
          $hostsContent = Get-Content $localHostsPath -ErrorAction Stop
      }
      catch {
          Write-Error \"Failed to load the HOSTS file. Error: $_\"
          return
      }

      # Initialize flags and buffer for new content
      $recording = $true
      $newContent = @()

      # Iterate over each line of the HOSTS file
      foreach ($line in $hostsContent) {
          if ($line -match \"#AdobeNetBlock-start\") {
              $recording = $false
          }
          if ($recording) {
              $newContent += $line
          }
          if ($line -match \"#AdobeNetBlock-end\") {
              $recording = $true
          }
      }

      # Write the filtered content back to the HOSTS file
      try {
          $newContent | Set-Content $localHostsPath -Encoding ASCII
          Write-Output \"Successfully removed the AdobeNetBlock section from the HOSTS file.\"
      }
      catch {
          Write-Error \"Failed to write back to the HOSTS file. Error: $_\"
      }

      # Flush the DNS resolver cache
      try {
          Invoke-Expression \"ipconfig /flushdns\"
          Write-Output \"DNS cache flushed successfully.\"
      }
      catch {
          Write-Error \"Failed to flush DNS cache. Error: $_\"
      }
      "
    ]
)
$f = @("Content": "Disable Notification Tray/Calendar",
    "Description": "Disables all Notifications INCLUDING Calendar",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a026_",
    "registry": [
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\Explorer",
        "Name": "DisableNotificationCenter",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
        "Name": "ToastEnabled",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ]
)
$f = @("Content": "Remove OneDrive",
    "Description": "Moves OneDrive files to Default Home Folders and Uninstalls it.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a030_",
    "InvokeScript": [
      "
      $OneDrivePath = $($env:OneDrive)
      Write-Host \"Removing OneDrive\"
      $regPath = \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OneDriveSetup.exe\"
      if (Test-Path $regPath){
          $OneDriveUninstallString = Get-ItemPropertyValue \"$regPath\" -Name \"UninstallString\"
          $OneDriveExe, $OneDriveArgs = $OneDriveUninstallString.Split(\" \")
          Start-Process -FilePath $OneDriveExe -ArgumentList \"$OneDriveArgs /silent\" -NoNewWindow -Wait
      }
      else{
          Write-Host \"Onedrive dosn''t seem to be installed anymore\" -ForegroundColor Red
          return
      }
      # Check if OneDrive got Uninstalled
      if (-not (Test-Path $regPath)){
      Write-Host \"Copy downloaded Files from the OneDrive Folder to Root UserProfile\"
      Start-Process -FilePath powershell -ArgumentList \"robocopy ''$($OneDrivePath)'' ''$($env:USERPROFILE.TrimEnd())\\'' /mov /e /xj\" -NoNewWindow -Wait

      Write-Host \"Removing OneDrive leftovers\"
      Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:localappdata\\Microsoft\\OneDrive\"
      Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:localappdata\\OneDrive\"
      Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:programdata\\Microsoft OneDrive\"
      Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$env:systemdrive\\OneDriveTemp\"
      reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\OneDrive\" -f
      # check if directory is empty before removing:
      If ((Get-ChildItem \"$OneDrivePath\" -Recurse | Measure-Object).Count -eq 0) {
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \"$OneDrivePath\"
      }

      Write-Host \"Remove Onedrive from explorer sidebar\"
      Set-ItemProperty -Path \"HKCR:\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Name \"System.IsPinnedToNameSpaceTree\" -Value 0
      Set-ItemProperty -Path \"HKCR:\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\" -Name \"System.IsPinnedToNameSpaceTree\" -Value 0

      Write-Host \"Removing run hook for new users\"
      reg load \"hku\\Default\" \"C:\\Users\\Default\\NTUSER.DAT\"
      reg delete \"HKEY_USERS\\Default\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"OneDriveSetup\" /f
      reg unload \"hku\\Default\"

      Write-Host \"Removing startmenu entry\"
      Remove-Item -Force -ErrorAction SilentlyContinue \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk\"

      Write-Host \"Removing scheduled task\"
      Get-ScheduledTask -TaskPath ''\\'' -TaskName ''OneDrive*'' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

      # Add Shell folders restoring default locations
      Write-Host \"Shell Fixing\"
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"AppData\" -Value \"$env:userprofile\\AppData\\Roaming\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Cache\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\INetCache\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Cookies\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\INetCookies\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Favorites\" -Value \"$env:userprofile\\Favorites\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"History\" -Value \"$env:userprofile\\AppData\\Local\\Microsoft\\Windows\\History\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Local AppData\" -Value \"$env:userprofile\\AppData\\Local\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Music\" -Value \"$env:userprofile\\Music\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Video\" -Value \"$env:userprofile\\Videos\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"NetHood\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"PrintHood\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Programs\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Recent\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Recent\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"SendTo\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\SendTo\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Start Menu\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Startup\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Templates\" -Value \"$env:userprofile\\AppData\\Roaming\\Microsoft\\Windows\\Templates\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{374DE290-123F-4565-9164-39C4925E467B}\" -Value \"$env:userprofile\\Downloads\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Desktop\" -Value \"$env:userprofile\\Desktop\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"My Pictures\" -Value \"$env:userprofile\\Pictures\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"Personal\" -Value \"$env:userprofile\\Documents\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{F42EE2D3-909F-4907-8871-4C22FC0BF756}\" -Value \"$env:userprofile\\Documents\" -Type ExpandString
      Set-ItemProperty -Path \"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\" -Name \"{0DDD015D-B06C-45D5-8C4C-F59713854639}\" -Value \"$env:userprofile\\Pictures\" -Type ExpandString
      Write-Host \"Restarting explorer\"
      taskkill.exe /F /IM \"explorer.exe\"
      Start-Process \"explorer.exe\"

      Write-Host \"Waiting for explorer to complete loading\"
      Write-Host \"Please Note - The OneDrive folder at $OneDrivePath may still have items in it. You must manually delete it, but all the files should already be copied to the base user folder.\"
      Write-Host \"If there are Files missing afterwards, please Login to Onedrive.com and Download them manually\" -ForegroundColor Yellow
      Start-Sleep 5
      }
      else{
      Write-Host \"Something went Wrong during the Unistallation of OneDrive\" -ForegroundColor Red
      }
      "
    ],
    "UndoScript": [
      "
      Write-Host \"Install OneDrive\"
      Start-Process -FilePath winget -ArgumentList \"install -e --accept-source-agreements --accept-package-agreements --silent Microsoft.OneDrive \" -NoNewWindow -Wait
      "
    ]
)
$f = @("Content": "Disable Intel MM (vPro LMS)",
    "Description": "Intel LMS service is always listening on all ports and could be a huge security risk. There is no need to run LMS on home machines and even in the Enterprise there are better solutions.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a026_",
    "InvokeScript": [
      "
        Write-Host \"Kill LMS\"
        $serviceName = \"LMS\"
        Write-Host \"Stopping and disabling service: $serviceName\"
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue;
        Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue;

        Write-Host \"Removing service: $serviceName\";
        sc.exe delete $serviceName;

        Write-Host \"Removing LMS driver packages\";
        $lmsDriverPackages = Get-ChildItem -Path \"C:\\Windows\\System32\\DriverStore\\FileRepository\" -Recurse -Filter \"lms.inf*\";
        foreach ($package in $lmsDriverPackages) {
            Write-Host \"Removing driver package: $($package.Name)\";
            pnputil /delete-driver $($package.Name) /uninstall /force;
        }
        if ($lmsDriverPackages.Count -eq 0) {
            Write-Host \"No LMS driver packages found in the driver store.\";
        } else {
            Write-Host \"All found LMS driver packages have been removed.\";
        }

        Write-Host \"Searching and deleting LMS executable files\";
        $programFilesDirs = @(\"C:\\Program Files\", \"C:\\Program Files (x86)\");
        $lmsFiles = @();
        foreach ($dir in $programFilesDirs) {
            $lmsFiles += Get-ChildItem -Path $dir -Recurse -Filter \"LMS.exe\" -ErrorAction SilentlyContinue;
        }
        foreach ($file in $lmsFiles) {
            Write-Host \"Taking ownership of file: $($file.FullName)\";
            & icacls $($file.FullName) /grant Administrators:F /T /C /Q;
            & takeown /F $($file.FullName) /A /R /D Y;
            Write-Host \"Deleting file: $($file.FullName)\";
            Remove-Item $($file.FullName) -Force -ErrorAction SilentlyContinue;
        }
        if ($lmsFiles.Count -eq 0) {
            Write-Host \"No LMS.exe files found in Program Files directories.\";
        } else {
            Write-Host \"All found LMS.exe files have been deleted.\";
        }
        Write-Host ''Intel LMS vPro service has been disabled, removed, and blocked.'';
       "
    ],
    "UndoScript": [
      "
      Write-Host \"LMS vPro needs to be redownloaded from intel.com\"

      "
    ]
)
$f = @("Content": "Disable Microsoft Copilot",
    "Description": "Disables MS Copilot AI built into Windows since 23H2.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a025_",
    "registry": [
      {
        "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        "Name": "TurnOffWindowsCopilot",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      },
      {
        "Path": "HKCU:\\Software\\Policies\\Microsoft\\Windows\\WindowsCopilot",
        "Name": "TurnOffWindowsCopilot",
        "Type": "DWord",
        "Value": "1",
        "OriginalValue": "0"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "Name": "ShowCopilotButton",
        "Type": "DWord",
        "Value": "0",
        "OriginalValue": "1"
      }
    ],
    "InvokeScript": [
      "
      Write-Host \"Remove Copilot\"
      dism /online /remove-package /package-name:Microsoft.Windows.Copilot
      "
    ],
    "UndoScript": [
      "
      Write-Host \"Install Copilot\"
      dism /online /add-package /package-name:Microsoft.Windows.Copilot
      "
    ]
)
$f = @("Content": "Disable Storage Sense",
    "Description": "Storage Sense deletes temp files automatically.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a005_",
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy\" -Name \"01\" -Value 0 -Type Dword -Force"
    ],
    "UndoScript": [
      "Set-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy\" -Name \"01\" -Value 1 -Type Dword -Force"
    ]
)
$f = @("Content": "Disable Powershell 7 Telemetry",
    "Description": "This will create an Environment Variable called &#39;POWERSHELL_TELEMETRY_OPTOUT&#39; with a value of &#39;1&#39; which will tell Powershell 7 to not send Telemetry Data.",
    "category": "Essential Tweaks",
    "panel": "1",
    "Order": "a009_",
    "InvokeScript": [
      "[Environment]::SetEnvironmentVariable(''POWERSHELL_TELEMETRY_OPTOUT'', ''1'', ''Machine'')"
    ],
    "UndoScript": [
      "[Environment]::SetEnvironmentVariable(''POWERSHELL_TELEMETRY_OPTOUT'', '''', ''Machine'')"
    ]
)
$f = @("Content": "Create Restore Point",
    "Description": "Creates a restore point at runtime in case a revert is needed from WinUtil modifications",
    "category": "Essential Tweaks",
    "panel": "1",
    "Checked": "False",
    "Order": "a001_",
    "InvokeScript": [
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
$f = @("Content": "Remove ALL MS Store Apps - NOT RECOMMENDED",
    "Description": "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a028_",
    "appx": [
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
    "InvokeScript": [
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
$f = @("Content": "Set Display for Performance",
    "Description": "Sets the system preferences to performance. You can do this manually with sysdm.cpl as well.",
    "category": "z__Advanced Tweaks - CAUTION",
    "panel": "1",
    "Order": "a027_",
    "registry": [
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "DragFullWindows",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop",
        "OriginalValue": "1",
        "Name": "MenuShowDelay",
        "Value": "200",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Desktop\\WindowMetrics",
        "OriginalValue": "1",
        "Name": "MinAnimate",
        "Value": "0",
        "Type": "String"
      },
      {
        "Path": "HKCU:\\Control Panel\\Keyboard",
        "OriginalValue": "1",
        "Name": "KeyboardDelay",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewAlphaSelect",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ListviewShadow",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarAnimations",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects",
        "OriginalValue": "1",
        "Name": "VisualFXSetting",
        "Value": "3",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\DWM",
        "OriginalValue": "1",
        "Name": "EnableAeroPeek",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarMn",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "TaskbarDa",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "OriginalValue": "1",
        "Name": "ShowTaskViewButton",
        "Value": "0",
        "Type": "DWord"
      },
      {
        "Path": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Search",
        "OriginalValue": "1",
        "Name": "SearchboxTaskbarMode",
        "Value": "0",
        "Type": "DWord"
      }
    ],
    "InvokeScript": [
      "Set-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))"
    ],
    "UndoScript": [
      "Remove-ItemProperty -Path \"HKCU:\\Control Panel\\Desktop\" -Name \"UserPreferencesMask\""
    ]
)
$f = @($dns = '{
    "Google": {
      "Primary": "8.8.8.8",
      "Secondary": "8.8.4.4",
      "Primary6": "2001:4860:4860::8888",
      "Secondary6": "2001:4860:4860::8844"
    },
    "Cloudflare": {
      "Primary": "1.1.1.1",
      "Secondary": "1.0.0.1",
      "Primary6": "2606:4700:4700::1111",
      "Secondary6": "2606:4700:4700::1001"
    },
    "Cloudflare_Malware": {
      "Primary": "1.1.1.2",
      "Secondary": "1.0.0.2",
      "Primary6": "2606:4700:4700::1112",
      "Secondary6": "2606:4700:4700::1002"
    },
    "Cloudflare_Malware_Adult": {
      "Primary": "1.1.1.3",
      "Secondary": "1.0.0.3",
      "Primary6": "2606:4700:4700::1113",
      "Secondary6": "2606:4700:4700::1003"
    },
    "Open_DNS": {
      "Primary": "208.67.222.222",
      "Secondary": "208.67.220.220",
      "Primary6": "2620:119:35::35",
      "Secondary6": "2620:119:53::53"
    },
    "Quad9": {
      "Primary": "9.9.9.9",
      "Secondary": "149.112.112.112",
      "Primary6": "2620:fe::fe",
      "Secondary6": "2620:fe::9"
    },
    "AdGuard_Ads_Trackers": {
      "Primary": "94.140.14.14",
      "Secondary": "94.140.15.15",
      "Primary6": "2a10:50c0::ad1:ff",
      "Secondary6": "2a10:50c0::ad2:ff"
    },
    "AdGuard_Ads_Trackers_Malware_Adult": {
      "Primary": "94.140.14.15",
      "Secondary": "94.140.15.16",
      "Primary6": "2a10:50c0::bad1:ff",
      "Secondary6": "2a10:50c0::bad2:ff"
    }
  }'
)
$f = @( reg / power 381b4222-f694-41f0-9685-ff5bb260df2e
)
$f = @(
)
$f = @(
)
$f = @(
)


HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState
FullPath =@{ Enable = 1 , Disable} # Display full path in the title bar

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
HideDrivesWithNoMedia = @{Enable = 1}

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
ShowSuperHidden = @{Value = 1}

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
AutoCheckSelect = @{Value = 1} # use check box to select items

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace
PenWorkspaceButtonDesiredVisibility = 1 # show pin menu icon when pen in use

HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7
TipbandDesiredVisibility = 1 # Show touch keyboard icon

Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
Start_Layout = 1 # set Start Layout to More pin

Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start
ShowFrequentList = 1 # Show most used Apps

Computer\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start
VisiblePlaces Binary = [byte[]]@(0xbc ,0x24 ,0x8a ,0x14 ,0x0c ,0xd6 ,0x89 ,0x42 ,0xa0 ,0x80 ,0x6e ,0xd9 ,0xbb ,0xa2 ,0x48 ,0x82 ,0xce ,0xd5 ,0x34 ,0x2d ,0x5a ,0xfa ,0x43 ,0x45 ,0x82 ,0xf2 ,0x22 ,0xe6 ,0xea ,0xf7 ,0x77 ,0x3c ,0x2f ,0xb3 ,0x67 ,0xe3 ,0xde ,0x89 ,0x55 ,0x43 ,0xbf ,0xce ,0x61 ,0xf3 ,0x7b ,0x18 ,0xa9 ,0x37 ,0xa0 ,0x07 ,0x3f ,0x38 ,0x0a ,0xe8 ,0x80 ,0x4c ,0xb0 ,0x5a ,0x86 ,0xdb ,0x84 ,0x5d ,0xbc ,0x4d ,0xc5 ,0xa5 ,0xb3 ,0x42 ,0x86 ,0x7d ,0xf4 ,0x42 ,0x80 ,0xa4 ,0x93 ,0xfa ,0xca ,0x7a ,0x88 ,0xb5 ,0x86 ,0x08 ,0x73 ,0x52 ,0xaa ,0x51 ,0x43 ,0x42 ,0x9f ,0x7b ,0x27 ,0x76 ,0x58 ,0x46 ,0x59 ,0xd4 ,0x44 ,0x81 ,0x75 ,0xfe ,0x0d ,0x08 ,0xae ,0x42 ,0x8b ,0xda ,0x34 ,0xed ,0x97 ,0xb6 ,0x63 ,0x94)

HKEY_CURRENT_USER\Software\Microsoft\Clipboard
EnableClipboardHistory = 1 #Enable clipboard

#set autoplay to take no action
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival
(Default) = string = MSTakeNoAction
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival
(Default) = string = MSTakeNoAction
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival
(Default) = string = MSTakeNoAction
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival
(Default) = string = MSTakeNoAction






