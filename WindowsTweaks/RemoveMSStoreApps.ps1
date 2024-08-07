function Remove-APPX {
    <#
    .SYNOPSIS
        Removes all APPX packages that match the given name

    .PARAMETER Name
        The name of the APPX package to remove

    .EXAMPLE
        Remove-APPX -Name "Microsoft.Microsoft3DViewer"
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Try {
        Write-Host "Removing $Name" -ForegroundColor Cyan
        Get-AppxPackage "*$Name*" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 100
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Name*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Catch [System.Exception] {
        if ($PSItem.Exception.Message -like "*The requested operation requires elevation*") {
            Write-Warning "Unable to uninstall $Name due to a Security Exception"
        }
        else {
            Write-Warning "Unable to uninstall $Name due to unhandled exception"
            Write-Warning $PSItem.Exception.StackTrace
        }
    }
}

Write-Host "Remove ALL MS Store Apps - NOT RECOMMENDED" -ForegroundColor Green
Write-Host "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!" -ForegroundColor DarkYellow

$Appx = @(
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    "Microsoft.GamingServices"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.YourPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.ScreenSketch"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*HotspotShieldFreeVPN*"
    "*Microsoft.Advertising.Xaml*"
)
$Appx | ForEach-Object {
    Remove-APPX -Name $PSItem
    Start-Sleep -Milliseconds 100
}

Write-Host "Removing MS Teams" -ForegroundColor Blue

$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Teams")
$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, "Update.exe")

Write-Host "Stopping Teams process..." -ForegroundColor Cyan
Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue

Write-Host "Uninstalling Teams from AppData\Microsoft\Teams" -ForegroundColor Cyan
if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
    # Uninstall app
    Start-Process $TeamsUpdateExePath "-uninstall -s" -NoNewWindow -Wait
}

Write-Host "Removing Teams AppxPackage..." -ForegroundColor Cyan
Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

Write-Host "Deleting Teams directory" -ForegroundColor Cyan
if ([System.IO.Directory]::Exists($TeamsPath)) {
    Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
}

Write-Host "Deleting Teams uninstall registry key" -ForegroundColor Cyan
# Uninstall from Uninstall registry key UninstallString
$us = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Teams*" }).UninstallString
if ($us.Length -gt 0) {
    $us = ($us.Replace("/I", "/uninstall ") + " /quiet").Replace("  ", " ")
    $FilePath = ($us.Substring(0, $us.IndexOf(".exe") + 4).Trim())
    $ProcessArgs = ($us.Substring($us.IndexOf(".exe") + 5).Trim().replace("  ", " "))
    Start-Process -FilePath $FilePath -Args $ProcessArgs -NoNewWindow -Wait
}
