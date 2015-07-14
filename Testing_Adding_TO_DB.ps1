$cred = Get-Credential
$username = 'unver_dv4'
$PWord = ConvertTo-SecureString –String "password" –AsPlainText -Force
$sqlobject = Get-VulnerableHosts -targetip "128.206.9.54,128.206.191.155,128.206.191.185" -QID "6" -credential $cred

write-host $sqlobject
write-host "sqlobject | gm"
$sqlobject | gm

for ($i=0;$i -le $sqlobject.Count;$i++){
$sqlobject | Send-QualysNotifications
$sqlobject[$i] | Save-HostInformationToDatabase 
$sqlobject[$i] | Get-Member
}