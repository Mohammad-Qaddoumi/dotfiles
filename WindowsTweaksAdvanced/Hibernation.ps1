# TODO: Implement this
$f = @(Content = "Set Hibernation as default (good for laptops)"
    Description = "Most modern laptops have connected stadby enabled which drains the battery, this sets hibernation as default which will not drain the battery. See issue https://github.com/ChrisTitusTech/winutil/issues/1399"
    registry = {
      {
        Name = "Attributes"
        Type = "DWord"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0"
        Value = "2"
        OriginalValue = "1"
      }
      {
        Name = "Attributes "
        Type = "DWord"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\94ac6d29-73ce-41a6-809f-6363ba21b47e"
        Value = "2"
        OriginalValue = "0"
      }
      {
        Path = "HKLM:\System\CurrentControlSet\Control\Session Manager\Power"
        Name = "HibernateEnabled"
        Type = "DWord"
        Value = "0"
        OriginalValue = "1"
      }
      {
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
        Name = "ShowHibernateOption"
        Type = "DWord"
        Value = "0"
        OriginalValue = "1"
      }
    }
    InvokeScript = {
      Write-Host "Turn on Hibernation"
      Start-Process -FilePath powercfg -ArgumentList "/hibernate on" -NoNewWindow -Wait

      # Set hibernation as the default action
      Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-ac 60" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-dc 60" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-ac 10" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-dc 1" -NoNewWindow -Wait
      
    }
    UndoScript = {
      Write-Host "Turn off Hibernation"
      Start-Process -FilePath powercfg -ArgumentList "/hibernate off" -NoNewWindow -Wait

      # Set standby to detault values
      Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-ac 15" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change standby-timeout-dc 15" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-ac 15" -NoNewWindow -Wait
      Start-Process -FilePath powercfg -ArgumentList "/change monitor-timeout-dc 15" -NoNewWindow -Wait
      
    }
)
$f=$f