& .\InstallFonts.ps1

function Copy-ItemWithCheck {
    param (
        [string]$sourcePath,
        [string]$destinationPath
    )

    # Check if the source path exists
    if (Test-Path -Path $sourcePath) {
        # Determine if the source path is a file or a folder
        $item = Get-Item -Path $sourcePath
        if ($item.PSIsContainer) {
            # It's a folder, create the destination folder if it does not exist
            if (-not (Test-Path -Path $destinationPath)) {
                New-Item -ItemType Directory -Path $destinationPath
            }
            # Copy the folder recursively
            Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force
            Write-Output "Folder copied successfully from $sourcePath to $destinationPath."
        } else {
            # It's a file, create the destination folder if it does not exist
            $destinationFolder = Split-Path -Parent $destinationPath
            if (-not (Test-Path -Path $destinationFolder)) {
                New-Item -ItemType Directory -Path $destinationFolder
            }
            # Copy the file
            Copy-Item -Path $sourcePath -Destination $destinationPath -Force
            Write-Output "File copied successfully from $sourcePath to $destinationPath."
        }
    } else {
        Write-Output "Source path $sourcePath does not exist."
    }
}

Copy-ItemWithCheck -sourcePath ".\PowerShell" -destinationPath "$env:USERPROFILE\Documents"
Copy-ItemWithCheck -sourcePath ".\WindowsTerminal\settings.json" -destinationPath "$env:USERPROFILE\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
