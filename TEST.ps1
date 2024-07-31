# Log outputs to a file
# $scriptDirectory = Split-Path -Parent $PSCommandPath
# $logFile = "$scriptDirectory\LogFile.txt"
# Start-Transcript -Path $logFile -Append

Write-Host "Start the script testing" -ForegroundColor Green
Write-Host "===================================`n`n" -ForegroundColor Gray



$registry = @(
    @{
    Path= "HKCU:\Control Panel\Desktop"
    Name= "DragFullWindows"
    Value= "0"
    Type= "String"
    }
    @{
    Path= "HKCU:\Control Panel\Desktop"
    OriginalValue= "1"
    Name= "MenuShowDelay"
    Value= "200"
    Type= "String"
    }
    @{
    Path= "HKCU:\Control Panel\Desktop\WindowMetrics"
    OriginalValue= "1"
    Name= "MinAnimate"
    Value= "0"
    Type= "String"
    }
    @{
    Path= "HKCU:\Control Panel\Keyboard"
    OriginalValue= "1"
    Name= "KeyboardDelay"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    OriginalValue= "1"
    Name= "ListviewAlphaSelect"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    OriginalValue= "1"
    Name= "ListviewShadow"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    OriginalValue= "1"
    Name= "TaskbarAnimations"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    OriginalValue= "1"
    Name= "VisualFXSetting"
    Value= "3"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\DWM"
    OriginalValue= "1"
    Name= "EnableAeroPeek"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Name= "TaskbarMn"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Name= "TaskbarDa"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    OriginalValue= "1"
    Name= "ShowTaskViewButton"
    Value= "0"
    Type= "DWord"
    }
    @{
    Path= "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    OriginalValue= "1"
    Name= "SearchboxTaskbarMode"
    Value= "0"
    Type= "DWord"
    }
    InvokeScript= [
      Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    ]
)

@{ Message = "Set Display for Performance" # Sets the system preferences to performance. You can do this manually with sysdm.cpl as well
        Data = @(
            @{
                Name = ""
                Type = ""
                Path = ""
                Value = ""
            }
        )
    }


@{ Message = ""
        Data = @(
            @{
                Name = ""
                Type = ""
                Path = ""
                Value = ""
            }
        )
    }


@{ Message = ""
        Data = @(
            @{
                Name = ""
                Type = ""
                Path = ""
                Value = ""
            }
        )
    }









# Stop-Transcript

# # Pause to allow viewing of the script output
# Pause
