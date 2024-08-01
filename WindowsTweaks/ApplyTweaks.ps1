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
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-ServiceStartupType {
    <#
    .SYNOPSIS
        Changes the startup type of the given service
    .EXAMPLE
        Set-WinUtilService -Name "HomeGroupListener" -StartupType "Manual"
    #>
    param (
        $Name,
        $StartupType
    )
    try {
        Write-Host "Setting Service $Name to $StartupType" -ForegroundColor Cyan

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
function Enable-LegacyF8BootRecovery{ # Enables Advanced Boot Options screen that lets you start Windows in advanced troubleshooting modes
    Write-Host "Enable Legacy F8 Boot Recovery (Advanced Boot Options screen)" -ForegroundColor Green
    $RegData = @{
        Name = "Enabled"
        Type = "DWord"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\LastKnownGood"
        Value = "0"
    }
    Set-Registry -Name $RegData.Name -Path $RegData.Path -Type $RegData.Type -Value $RegData.Value
    Try{
        Start-Process -FilePath cmd.exe -ArgumentList "/c bcdedit /Set {Current} BootMenuPolicy Standard" -Wait
    }
    Catch{
        Write-Warning "Unable to set BootMenuPolicy due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Disable-Teredo{ # Teredo network tunneling is a ipv6 feature that can cause additional latency
    Write-Host "Disable Teredo (ipv6 feature that can cause additional latency)" -ForegroundColor Green
    $RegData = @{
        Name = "DisabledComponents"
        Type = "DWord"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        Value = "1"
        OriginalValue = "0"
        <#
            0x00: Default value; all IPv6 components are enabled.
            0x01: Disable the creation of IPv6 global unique addresses.
            0x02: Disable the IPv6 tunnel interfaces (6to4, ISATAP, etc.).
            0x10: Disable native IPv6 over the Ethernet interfaces.
            0x20: Prefer IPv4 over IPv6.
            0xFF: Disable all IPv6 components.
            For example, setting the value to 0x20 will prefer IPv4 over IPv6, while 0xFF will disable IPv6 entirely.
        #>
    }
    Set-Registry -Name $RegData.Name -Path $RegData.Path -Type $RegData.Type -Value $RegData.Value
    Try{
        netsh interface teredo set state disabled
        <#
        UndoScript = 
            netsh interface teredo set state default
        #>
    }
    Catch{
        Write-Warning "Unable to disable teredo due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
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
                Write-Host "Ultimate Performance plan is already installed."
            } else {
                Write-Host "Installing Ultimate Performance plan..."
                powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
                Write-Host "> Ultimate Performance plan installed."
            }

            # Set the Ultimate Performance plan as active
            $ultimatePlanGUID = (powercfg -list | Select-String -Pattern "Ultimate Performance").Line.Split()[3]
            powercfg -setactive $ultimatePlanGUID

            Write-Host "Ultimate Performance plan is now active."
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

                Write-Host "Ultimate Performance plan has been uninstalled."
                Write-Host "> Balanced plan is now active."
            } else {
                Write-Host "Ultimate Performance plan is not installed."
            }
        }
    } Catch{
        Write-Warning $psitem.Exception.Message
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

# To Use "HKU:\" reg path instaed of "Registry::HKU\"
if (!(Test-Path 'HKU:')) { 
    Write-Host "Creating HKU: drive..." -ForegroundColor Yellow
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS 
}

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
Enable-LegacyF8BootRecovery

Write-Host "`n================================================================"
Disable-Teredo

# Source the variable definition script (List of Services Collection)
. ".\ServicesCollection.ps1"
Write-Host "`n================================================================"
Write-Host $ServicesCollection.Description -ForegroundColor Green
foreach($service in $ServicesCollection.service){
    Write-Host "`n================================================================"
    Set-ServiceStartupType -Name $service.Name -StartupType $service.StartupType
}

