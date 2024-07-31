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
        Write-Host "Setting registry key: $Name at $subKey.PSPath" -ForegroundColor Cyan
        $Path = $subKey.PSPath
    
        if ($values.IconGuid -eq "{7820AE78-23E3-4229-82C1-E41CB67D5B9C}" -and $values.ExecutablePath -eq "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe" ){
            #Write-Host "FOUND IT" -ForegroundColor Green
            $Enable = 1
        }
        else{
            $Enable = 0
        }
        Try{
            # Ensure the registry key exists
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            # Set the property, creating it if it doesn''t exist
            New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Enable -Force | Out-Null
        }
        Catch [System.Security.SecurityException] {
            Write-Warning "Unable to set $Path\$Name to $Enable due to a Security Exception"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning $psitem.Exception.ErrorRecord
        }
        Catch{
            Write-Warning "Unable to set $Name due to unhandled exception"
            Write-Warning $psitem.Exception.StackTrace
        }
    }
}
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