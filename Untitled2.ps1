function Parse-CSV ([string]$csv){
$regex = (^"Remote operating system : "$)
$a = Import-Csv 'C:\Users\JAR\Desktop\128.206.0 OS_ID_Scan_4_xvnnhm - TEST.csv'
#$a."Plugin Output" -match $regex # | Select-Object -Property "Host","Plugin Output"
$a | ft Host,"Plugin Output"
}