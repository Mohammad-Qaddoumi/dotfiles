# Log outputs to a file
# $scriptDirectory = Split-Path -Parent $PSCommandPath
# $logFile = "$scriptDirectory\LogFile.txt"
# Start-Transcript -Path $logFile -Append

Write-Host "Start the script testing" -ForegroundColor Green
Write-Host "===================================`n`n" -ForegroundColor Gray







# @{ Message = ""
#         Data = @(
#             @{
#                 Name = ""
#                 Type = ""
#                 Path = ""
#                 Value = ""
#             }
#         )
#     }

# @{ Message = ""
#         Data = @(
#             @{
#                 Name = ""
#                 Type = ""
#                 Path = ""
#                 Value = ""
#             }
#         )
#     }

# @{ Message = ""
#         Data = @(
#             @{
#                 Name = ""
#                 Type = ""
#                 Path = ""
#                 Value = ""
#             }
#         )
#     }







# Stop-Transcript

# # Pause to allow viewing of the script output
# Pause


# To Get AUMID to use in StartLayout
<#
$installedapps = Get-AppxPackage

$aumidList = @()
foreach ($app in $installedapps)
{
    foreach ($id in (Get-AppxPackageManifest $app).package.applications.application.id)
    {
        $aumidList += $app.packagefamilyname + "!" + $id
    }
}

$aumidList
#>
