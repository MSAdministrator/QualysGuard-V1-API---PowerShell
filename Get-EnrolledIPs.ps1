function Get-EnrolledIPs (){
param (
        [parameter(ParameterSetName="set1")] $ipaddress,
        [parameter(ParameterSetName="set2")] $dnsname,
        [parameter(ParameterSetName="set3")] $netbios,
        [System.Management.Automation.CredentialAttribute()]$credential
            ) 

$file1 = "C:\users\rickardj\Desktop\enrolled_qualys_ips.txt"
$file2 = "C:\Users\rickardj\Desktop\csg_vm_list.txt"

[xml]$QualysIPs = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_ip_list.php?detailed_results=1&detailed_no_results=1" -Credential $credential

#Get-Content C:\Users\rickardj\Desktop\csg_vm_list.txt | ForEach-Object {

$scannednonrangeip = $QualysIPs.HOST_LIST.RESULTS.HOST.IP.'#cdata-section'
$startnonscannedip = $QualysIPs.HOST_LIST.NO_RESULTS.TRACKING_METHOD_LIST.TRACKING_METHOD.IP_LIST.RANGE.START.'#cdata-section'
$endnonscannedip = $QualysIPs.HOST_LIST.NO_RESULTS.TRACKING_METHOD_LIST.TRACKING_METHOD.IP_LIST.RANGE.END.'#cdata-section'

$start = $QualysIPs.HOST_LIST.IP_LIST.RANGE.START.'#cdata-section'
$end = $QualysIPs.HOST_LIST.IP_LIST.RANGE.END.'#cdata-section'


foreach ($ip in $scannednonrangeip){
    [array]$iplist += $ip
    }
$iplist.Count
foreach ($ip in $startnonscannedip){
    [array]$iplist += $ip
    }
$iplist.Count
foreach ($ip in $endnonscannedip){
    [array]$iplist += $ip
    }
$iplist.Count


for ($i=0;$i -le $end.count;$i++){

    if ($start[$i] -ne $end[$i]){
        $expandedipranges = Get-IPrange -start $start[$i] -end $end[$i]            
    }
}

foreach ($ip in $expandedipranges){
    [array]$iplist += $ip
    }

$iplist.Count

$iplist | select -Unique

#> C:\Users\rickardj\Desktop\enrolled_qualys_ips.txt

#$compare = Compare-Object -referenceobject $(get-content $file1) -differenceobject $(get-content $file2) -IncludeEqual


#$compare | foreach  { 
 #     if ($_.sideindicator -eq '<=')
 #       {$_.sideindicator = $file1}
#
#      if ($_.sideindicator -eq '=>')
#        {$_.sideindicator = $file2}
#     }

 #     $Compare | 
 #  select @{l='Value';e={$_.InputObject}},@{l='File';e={$_.SideIndicator}} |
 #  Out-File C:\Users\rickardj\Desktop\outfile.txt

  #Write-Host "Complete!"

}

