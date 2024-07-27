$command = "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine"

$process1 = Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
$process1.WaitForExit()

$process2 = Start-Process pwsh -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
$process2.WaitForExit()
