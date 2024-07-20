$WINGET_PROGRAMS_ID = @(
    "Microsoft.PowerShell",
    "Microsoft.WindowsTerminal",
    "JanDeDobbeleer.OhMyPosh",
    "Git.Git",
    "GitHub.cli"
    # "PDFLabs.PDFtk.Free", # PDF merge
    # "Google.GoogleDrive",
    # "Mozilla.Firefox",
    # "Avidemux.Avidemux",
    # "Mega.MEGASync",
    # "Gyan.FFmpeg",
    # "Brave.Brave",
    # "calibre.calibre",
    # "HandBrake.HandBrake",
    # "KDE.Kdenlive",
    # "TheDocumentFoundation.LibreOffice",
    # "Cyanfish.NAPS2",
    # "OpenJS.NodeJS",
    # "OBSProject.OBSStudio",
    # "Oracle.VirtualBox",
    # "Postman.Postman",
    # "Python.Python.3.13",
    # "RevoUninstaller.RevoUninstaller",
    # "Telegram.TelegramDesktop",
    # "CodeSector.TeraCopy",
    # "TorProject.TorBrowser",
    # "qBittorrent.qBittorrent",
    # "VideoLAN.VLC",
    # "Zoom.Zoom"
    )

# Suppress the warning for this variable
$WINGET_PROGRAMS_ID = $WINGET_PROGRAMS_ID # PSScriptAnalyzer disable:PSUseDeclaredVarsMoreThanAssignments
