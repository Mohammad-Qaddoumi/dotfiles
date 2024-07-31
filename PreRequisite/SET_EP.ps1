$command = "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine"

Start-Process powershell -Verb RunAs -NoNewWindow -Wait -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""

Start-Process pwsh -Verb RunAs -NoNewWindow -Wait -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
