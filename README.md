# dotfiles And settings

 - Nothing here is ready yet , maybe after a year 😒...
 
 - For me change [push.ps1](https://github.com/Qaddoumi/dotfiles/blob/master/push.ps1) Location

# How to use

## option 1

  - Use this code in powershell to download the files and extract into desktop
  ```powershell
  $url = "https://github.com/Qaddoumi/dotfiles/archive/refs/heads/master.zip"; $destinationPath = ([Environment]::GetFolderPath('Desktop')); Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\temp.zip"; Expand-Archive -Path "$env:TEMP\temp.zip" -DestinationPath $destinationPath -Force; Remove-Item "$env:TEMP\temp.zip";Set-Location "$destinationPath\dotfiles-master";
  ```

 - Run [RunFirst.bat](https://github.com/Qaddoumi/dotfiles/blob/master/RunFirst.bat) To Install All pre requisite.
 
 - RunFirst should start [RunSecound.bat](https://github.com/Qaddoumi/dotfiles/blob/master/RunSecond.bat) by itself but 
   if it did not start it manully

## option 2

 - Download and run
  ```powershell
  $url = "https://github.com/Qaddoumi/dotfiles/archive/refs/heads/master.zip"; $destinationPath = ([Environment]::GetFolderPath('Desktop')); Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\temp.zip"; Expand-Archive -Path "$env:TEMP\temp.zip" -DestinationPath $destinationPath -Force; Remove-Item "$env:TEMP\temp.zip";Set-Location "$destinationPath\dotfiles-master";& .\RunFirst.bat;
  ```


# Credit to :
 - [winget-install](https://github.com/asheroto/winget-install)
 - [winutil](https://github.com/ChrisTitusTech/winutil)
