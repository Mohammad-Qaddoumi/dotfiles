
Function Invoke-WinUtilDarkMode {
    <#

    .SYNOPSIS
        Enables/Disables Dark Mode

    .PARAMETER DarkMoveEnabled
        Indicates the current dark mode state

    #>
    Param($DarkMoveEnabled)
    Try{
        if ($DarkMoveEnabled -eq $false){
            Write-Host "Enabling Dark Mode"
            $DarkMoveValue = 0
        }
        else {
            Write-Host "Disabling Dark Mode"
            $DarkMoveValue = 1
        }

        $Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty -Path $Path -Name AppsUseLightTheme -Value $DarkMoveValue
        Set-ItemProperty -Path $Path -Name SystemUsesLightTheme -Value $DarkMoveValue
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

function Invoke-WinUtilBingSearch {
    <#

    .SYNOPSIS
        Disables/Enables Bing Search

    .PARAMETER Enabled
        Indicates whether to enable or disable Bing Search

    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Bing Search"
            $value = 1
        }
        else {
            Write-Host "Disabling Bing Search"
            $value = 0
        }
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        Set-ItemProperty -Path $Path -Name BingSearchEnabled -Value $value
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

function Invoke-WinUtilFeatureInstall {
    <#

    .SYNOPSIS
        Converts all the values from the tweaks.json and routes them to the appropriate function

    #>

    param(
        $CheckBox
    )

    $CheckBox | ForEach-Object {
        if($sync.configs.feature.$psitem.feature){
            Foreach( $feature in $sync.configs.feature.$psitem.feature ){
                Try{
                    Write-Host "Installing $feature"
                    Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
                }
                Catch{
                    if ($psitem.Exception.Message -like "*requires elevation*"){
                        Write-Warning "Unable to Install $feature due to permissions. Are you running as admin?"
                    }

                    else{
                        Write-Warning "Unable to Install $feature due to unhandled exception"
                        Write-Warning $psitem.Exception.StackTrace
                    }
                }
            }
        }
        if($sync.configs.feature.$psitem.InvokeScript){
            Foreach( $script in $sync.configs.feature.$psitem.InvokeScript ){
                Try{
                    $Scriptblock = [scriptblock]::Create($script)

                    Write-Host "Running Script for $psitem"
                    Invoke-Command $scriptblock -ErrorAction stop
                }
                Catch{
                    if ($psitem.Exception.Message -like "*requires elevation*"){
                        Write-Warning "Unable to Install $feature due to permissions. Are you running as admin?"
                    }

                    else{
                        Write-Warning "Unable to Install $feature due to unhandled exception"
                        Write-Warning $psitem.Exception.StackTrace
                    }
                }
            }
        }
    }
}

function Invoke-WinUtilGPU {
    $gpuInfo = Get-CimInstance Win32_VideoController

    # GPUs to blacklist from using Demanding Theming
    $lowPowerGPUs = (
        "*NVIDIA GeForce*M*",
        "*NVIDIA GeForce*Laptop*",
        "*NVIDIA GeForce*GT*",
        "*AMD Radeon(TM)*",
        "*UHD*"
    )

    foreach ($gpu in $gpuInfo) {
        foreach ($gpuPattern in $lowPowerGPUs){
            if ($gpu.Name -like $gpuPattern) {
                return $false
            }
        }
    }
    return $true
}

function Invoke-WinUtilHiddenFiles {
    <#

    .SYNOPSIS
        Enable/Disable Hidden Files

    .PARAMETER Enabled
        Indicates whether to enable or disable Hidden Files

    #>
    Param($Enabled)
    Try{
        if ($Enabled -eq $false){
            Write-Host "Enabling Hidden Files"
            $value = 1
        }
        else {
            Write-Host "Disabling Hidden Files"
            $value = 0
        }
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name Hidden -Value $value
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

