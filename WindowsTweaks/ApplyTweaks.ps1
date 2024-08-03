function Set-Registry {
    <#
    EXAMPLE
    Set-Registry -Name "PublishUserActivities" -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Type "DWord" -Value "0"
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "QWord", "MultiString")]
        [string]$Type,
        
        [object]$Value
    )
    If (!(Test-Path $Path)) {
        Write-Warning "$Path was not found, Creating..."
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    Try{
        Write-Host "Setting registry key: $Name at $Path" -ForegroundColor Cyan
        # Set the property, creating it if it doesn''t exist
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $PSItem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $PSItem.Exception.StackTrace
    }
}
function Set-ScheduledTask {
    <#
    .EXAMPLE
    Set-ScheduledTask -Name "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -State "Disabled"
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
        elseif($State -eq "Enabled"){
            Write-Host "Enabling Scheduled Task $Name"
            Enable-ScheduledTask -TaskName $Name -ErrorAction Stop
        }
    }
    Catch [System.Exception]{
        if($PSItem.Exception.Message -like "*The system cannot find the file specified*"){
            Write-Warning "Scheduled Task $Name was not Found"
        }
        Else{
            Write-Warning "Unable to set $Name due to unhandled exception"
            Write-Warning $PSItem.Exception.Message
        }
    }
    Catch{
        Write-Warning "Unable to run script for $Name due to unhandled exception"
        Write-Warning $PSItem.Exception.StackTrace
    }
}
function Set-ServiceStartupType {
    <#
    .SYNOPSIS
        Changes the startup type of the given service
    .EXAMPLE
        Set-ServiceStartupType -Name "HomeGroupListener" -StartupType "Manual" -OriginalType "Automatic"
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Automatic", "Manual", "Disabled", "AutomaticDelayedStart")]
        [string]$StartupType,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Automatic", "Manual", "Disabled", "AutomaticDelayedStart")]
        [string]$OriginalType
    )
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        if(!($service.StartType.ToString() -eq $OriginalType)) {
            Write-Host "Service $($service.Name) was changed in the past to $($service.StartType.ToString()) from it's original type of $OriginalType, will not change it to $StartupType" -ForegroundColor Cyan
        }
        else{
            Write-Host "$Name and state is $($service.StartType.ToString())" -ForegroundColor Cyan
            # Service exists, proceed with changing properties
            $service | Set-Service -StartupType $StartupType -ErrorAction Stop
        }
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        Write-Warning "Service '$Name' was not found."
    }
    catch {
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $PSItem.Exception.Message
    }
}
function Enable-UltimatePerformance {
    <#
    .SYNOPSIS
        Creates or removes the Ultimate Performance power scheme
    .PARAMETER State
        Indicates whether to enable or disable the Ultimate Performance power scheme
    #>
    $state = "Enable"
    Try{
        # Check if Ultimate Performance plan is installed
        $ultimatePlan = powercfg -list | Select-String -Pattern "Ultimate Performance"
        if($state -eq "Enable"){
            if ($ultimatePlan) {
                Write-Host "Ultimate Performance plan is already installed." -ForegroundColor Green
            } else {
                Write-Host "Installing Ultimate Performance plan..." -ForegroundColor Green
                powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
                Write-Host "> Ultimate Performance plan installed." -ForegroundColor Cyan
            }

            # Set the Ultimate Performance plan as active
            $ultimatePlanGUID = (powercfg -list | Select-String -Pattern "Ultimate Performance").Line.Split()[3]
            powercfg -setactive $ultimatePlanGUID

            Write-Host "Ultimate Performance plan is now active." -ForegroundColor Cyan
        }
        elseif($state -eq "Disable"){
            if ($ultimatePlan) {
                # Extract the GUID of the Ultimate Performance plan
                $ultimatePlanGUID = $ultimatePlan.Line.Split()[3]

                # Set a different power plan as active before deleting the Ultimate Performance plan
                $balancedPlanGUID = (powercfg -list | Select-String -Pattern "Balanced").Line.Split()[3]
                powercfg -setactive $balancedPlanGUID

                # Delete the Ultimate Performance plan
                powercfg -delete $ultimatePlanGUID

                Write-Host "Ultimate Performance plan has been uninstalled." -ForegroundColor Green
                Write-Host "> Balanced plan is now active." -ForegroundColor Cyan
            } else {
                Write-Host "Ultimate Performance plan is not installed." -ForegroundColor Yellow
            }
        }
    } Catch{
        Write-Warning $PSItem.Exception.Message
    }
}
function Show-IconsSysTray{
    $registryPath = "HKCU:\Control Panel\NotifyIconSettings"
    $subKeys = Get-ChildItem -Path $registryPath
    $Name = "IsPromoted"
    $Enable = 1
    Write-Host "Show Icons SysTray" -ForegroundColor Green
    foreach ($subKey in $subKeys) {
        # Check for specific values in the subkey that might identify "Safely Remove Hardware"
        $values = Get-ItemProperty -Path $subKey.PSPath
        #Write-Host $values
        if ($values.IconGuid -eq "{7820AE78-23E3-4229-82C1-E41CB67D5B9C}" -and $values.ExecutablePath -eq "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe" ){
            #Write-Host "FOUND IT" -ForegroundColor Green
            $Enable = 1
        }
        else{
            $Enable = 0
        }
        Set-Registry -Name $Name -Path $subKey.PSPath -Type "DWord" -Value $Enable
    }
}
function Disable-PowershellTelemetry{
    # This will create an Environment Variable called &#39;POWERSHELL_TELEMETRY_OPTOUT&#39; with a value of &#39;1&#39; which will tell Powershell 7 to not send Telemetry Data
    Write-Host "Disable Powershell 7 Telemetry" -ForegroundColor Green
    Write-Host "Setting Env `"POWERSHELL_TELEMETRY_OPTOUT`" To `"1`"" -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "Machine")
    # Undo
    # [Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "", "Machine")
}
function Remove-HomeGallery{
    Write-Host "Remove Home and Gallery from explorer" -ForegroundColor Green
    Write-Host "Removes the Home and Gallery from explorer and sets This PC as default" -ForegroundColor Cyan
    # Delete the first registry key
    Try {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Force -Recurse -ErrorAction SilentlyContinue
    }
    Catch {
        Write-Warning "Failed to remove the specified registry key"
        Write-Warning $PSItem.Exception.Message
    }
    # Delete the second registry key
    Try {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Force -Recurse -ErrorAction SilentlyContinue
    }
    Catch {
        Write-Warning "Failed to remove the specified registry key"
        Write-Warning $PSItem.Exception.Message
    }
    <#
    UndoScript =
    # Add the first registry key with a default value
    Set-Registry -Name "(Default)" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Type "String" -Value "{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"
    # Add the second registry key with a default value
    Set-Registry -Name "(Default)" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Type "String" -Value "CLSID_MSGraphHomeFolder"
    #>
}

# To Use "HKU:\" reg path instaed of "Registry::HKU\"
if (!(Test-Path 'HKU:')) { 
    Write-Host "Creating HKU: drive..." -ForegroundColor Yellow
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS 
}

Write-Host "`n================================================================" -NoNewline
# Source the variable definition script (List of Registry Settings)
. ".\RegistrySettings.ps1"
foreach($Setting in $RegistrySettings){
    Write-Host "`n================================================================"
    Write-Host $Setting.Message -ForegroundColor Green
    foreach($Entry in $Setting.Data){
        Set-Registry -Name $Entry.Name -Path $Entry.Path -Type $Entry.Type -Value $Entry.Value
    }
}

Write-Host "`n================================================================"
Show-IconsSysTray

Write-Host "`n================================================================"
Enable-UltimatePerformance

Write-Host "`n================================================================"
Disable-PowershellTelemetry

Write-Host "`n================================================================"
Remove-HomeGallery

Write-Host "`n================================================================"
# Source the variable definition script (List of Services Collection)
. ".\ServicesCollection.ps1"
Write-Host $ServicesCollection.Description -ForegroundColor Green
foreach($service in $ServicesCollection.service){
    Write-Host "`n================================================================"
    Set-ServiceStartupType -Name $service.Name -StartupType $service.StartupType -OriginalType $service.OriginalType
}

Write-Host "`n================================================================"
# Source the variable definition script (List of reg,sch,and function)
. ".\DisableTelemetry.ps1"
Write-Host "`nDisable Telemetry" -ForegroundColor Green
Write-Host "Disables Microsoft Telemetry. Note: This will lock many Edge Browser settings. Microsoft spies heavily on you when using the Edge browser.`n" -ForegroundColor Cyan
foreach ($Entry in $RegistrySettingsTele) {
    Set-Registry -Name $Entry.Name -Path $Entry.Path -Type $Entry.Type -Value $Entry.Value
}
foreach ($Entry in $ScheduledTaskSettings) {
    Set-ScheduledTask -Name $Entry.Name -State $Entry.State
}
Disable-Telemetry

Write-Host "`n================================================================"
& .\RemoveMSStoreApps.ps1
