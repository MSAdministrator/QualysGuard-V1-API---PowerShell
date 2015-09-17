#Expand each IP in $item.ip (which is each item in AssetGroupInfo)
    $expandedIPRange = @()
    $assetgroupIPs = @()
    foreach ($ipaddress in $($item.ip)){
        # write-host "ip: " $ip
        if ($ipaddress -match "-"){
            $splitip = $ipaddress -split '[\-]'
            for ($ip=0;$ip -lt $splitip.count;$ip++){
                write-host "splitiprange: " $splitip[$ip]
                if ($ip -eq "0"){
                    $startSplitIp = $splitip[$ip]
                    write-host "startsplitip: " $startSplitIp
                }
                else{
                    $endSplitIp = $splitip[$ip]
                                   
                    $ip1 = ([System.Net.IPAddress]$startSplitIp).GetAddressBytes()
                    [Array]::Reverse($ip1)
                    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

                    $ip2 = ([System.Net.IPAddress]$endSplitIp).GetAddressBytes()
                    [Array]::Reverse($ip2)
                    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

                    for ($x=$ip1; $x -le $ip2; $x++) {
                    $ips = ([System.Net.IPAddress]$x).GetAddressBytes()
                    [Array]::Reverse($ips)
                    $assetgroupIPs += $ips -join '.'
                    }
            }
        }
                       
    }
    else{  
        $assetgroupIPs += $ipaddress     
    }
} 