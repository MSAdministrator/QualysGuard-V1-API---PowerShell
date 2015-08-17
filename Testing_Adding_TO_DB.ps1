#$cred = Get-Credential
#$username = 'unver_dv4'
#$PWord = ConvertTo-SecureString –String "Vr4e2l9yehgutUP0wOU!" –AsPlainText -Force
$sqlobject = Get-VulnerableHost -ip "128.206.9.54,128.206.111.6" -QID "6" -credential $cred

#write-host $sqlobject
#write-host "sqlobject | gm"
#$sqlobject | gm
write-host "sqlobject count: " $sqlobject.Count
foreach ($object in $sqlobject){
#$sqlobject | Send-QualysNotifications
$object | Save-HostInformationToDatabase -Debug
#$sqlobject[$i] | Get-Member
}