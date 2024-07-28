# ************************************************
# Create WinUtil shortcut on the desktop
#
$desktopPath = "$($env:USERPROFILE)\Desktop"
# Specify the target PowerShell command
$command = "`$url = `"https://github.com/Qaddoumi/dotfiles/archive/refs/heads/master.zip`"; `$destinationPath = ([Environment]::GetFolderPath('Desktop'));Set-Location `"`$destinationPath`";if (Test-Path -Path `"`$destinationPath\dotfiles-master`"){Remove-Item -Recurse dotfiles-master -Force} ;Invoke-WebRequest -Uri `$url -OutFile `"`$env:TEMP\temp.zip`"; Expand-Archive -Path `"`$env:TEMP\temp.zip`" -DestinationPath `$destinationPath -Force; Remove-Item `"`$env:TEMP\temp.zip`";Set-Location `"`$destinationPath\dotfiles-master`";Write-Host `"`nRun .\RunFirst.bat`n`";"
# Specify the path for the shortcut
$shortcutPath = Join-Path $desktopPath 'winutil.lnk'
# Create a shell object
$shell = New-Object -ComObject WScript.Shell

# Create a shortcut object
$shortcut = $shell.CreateShortcut($shortcutPath)

# if (Test-Path -Path "c:\Windows\mylogo.png")
# {
#     $shortcut.IconLocation = "c:\Windows\mylogo.png"
# }
if (Test-Path -Path "$destinationPath\dotfiles-master"){Remove-Item -Recurse dotfiles-master -Force}
Write-Host `"`nRun .\RunFirst.bat`n`";

# Set properties of the shortcut
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
# Save the shortcut
$shortcut.Save()

# Make the shortcut have 'Run as administrator' property on
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
# Set byte value at position 0x15 in hex, or 21 in decimal, from the value 0x00 to 0x20 in hex
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "Shortcut created at: $shortcutPath"
#
# Done create WinUtil shortcut on the desktop
# ************************************************

Start-Process explorer