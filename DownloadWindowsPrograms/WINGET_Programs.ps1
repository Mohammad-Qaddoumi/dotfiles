$WINGET_PROGRAMS_ID = @(
    "JanDeDobbeleer.OhMyPosh", # powershell prompt
    "GitHub.cli"
    # "PDFLabs.PDFtk.Free", # PDF merge
    # "OpenJS.NodeJS",  # NodeJS
    # "Google.GoogleDrive",
    # "Mozilla.Firefox",
    # "Avidemux.Avidemux", # fast video split,cut ..
    # "Mega.MEGASync",
    # "Gyan.FFmpeg",
    # "Brave.Brave",
    # "calibre.calibre", # open book files like epub .. 
    # "HandBrake.HandBrake", # Video conversion
    # "KDE.Kdenlive", # Video editor,production ..
    # "ONLYOFFICE.DesktopEditors", # PDF Editor
    # "TheDocumentFoundation.LibreOffice", # For Documents
    # "Cyanfish.NAPS2", # OCR and merge for pdf
    # "OBSProject.OBSStudio", # video stream and record 
    # "Oracle.VirtualBox", # don't forgt to install VB Extenctions 
    # "Postman.Postman", # for backend request tests
    # "Python.Python.3.13",  # Python change the version
    # "RevoUninstaller.RevoUninstaller", # fully uninstall windows programs 
    # "Telegram.TelegramDesktop",
    # "CodeSector.TeraCopy", # file copy,paste
    # "TorProject.TorBrowser",
    # "qBittorrent.qBittorrent",
    # "VideoLAN.VLC",
    # "Zoom.Zoom"
)

# Suppress the warning for this variable
$WINGET_PROGRAMS_ID = $WINGET_PROGRAMS_ID # PSScriptAnalyzer disable:PSUseDeclaredVarsMoreThanAssignments
