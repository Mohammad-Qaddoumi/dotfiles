
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

$b = @{Content = "Remove ALL MS Store Apps - NOT RECOMMENDED"
    Description = "USE WITH CAUTION!!!!! This will remove ALL Microsoft store apps other than the essentials to make winget work. Games installed by MS Store ARE INCLUDED!"
    appx = {
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
      "Microsoft.WindowsPhone"
      "Microsoft.WindowsSoundRecorder"
      "Microsoft.XboxApp"
      "Microsoft.ConnectivityStore"
      "Microsoft.CommsPhone"
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
    }
    InvokeScript = {
      @( 
        $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Teams")
        $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, "Update.exe")

        Write-Host "Stopping Teams process..."
        Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue

        Write-Host "Uninstalling Teams from AppData\Microsoft\Teams"
        if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
            # Uninstall app
            $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
            $proc.WaitForExit()
        }

        Write-Host "Removing Teams AppxPackage..."
        Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

        Write-Host "Deleting Teams directory"
        if ([System.IO.Directory]::Exists($TeamsPath)) {
            Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
        }

        Write-Host "Deleting Teams uninstall registry key"
        # Uninstall from Uninstall registry key UninstallString
        $us = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Teams*"}).UninstallString
        if ($us.Length -gt 0) {
            $us = ($us.Replace("/I", "/uninstall ") + " /quiet").Replace("  ", " ")
            $FilePath = ($us.Substring(0, $us.IndexOf(".exe") + 4).Trim())
            $ProcessArgs = ($us.Substring($us.IndexOf(".exe") + 5).Trim().replace("  ", " "))
            $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
            $proc.WaitForExit()
        }
      )
    }
}

$sync.configs.tweaks.$CheckBox.appx | ForEach-Object {
  Write-Debug "UNDO $($psitem.Name)"
  Remove-WinUtilAPPX -Name $psitem
}
