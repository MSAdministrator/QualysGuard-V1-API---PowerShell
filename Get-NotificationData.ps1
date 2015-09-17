function Get-NotificationData {
[cmdletbinding()]
    param (      
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter a QID (Qualys ID) to search for")]
                   [ValidateCount(1,20)]
                   [ValidateNotNullOrEmpty()]
                   [string[]]$QID,
        
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please provide a crednetial obejct")]
                   [ValidateNotNullOrEmpty()]
                   [System.Management.Automation.CredentialAttribute()]$credential
        ) 
    
  
    <#
    .SYNOPSIS 
    Query's QualysGuard asset_search.php for a host or  hosts with a specific vulnerability

    .DESCRIPTION
    Query's the API to find details about a specific host
    Takes input as an IP(s), Asset Group title (string), and specific QID (Vulnerability)

    .PARAMETER ip
    Specify a single or a comma seperated list of IP addresses you are wanting to search

    .PARAMETER assetgroup
    Specifices a single or a comma seperated list of Asset Groups you are wanting to search
    Default value is "All"

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    You can pipe PSCustomObjects that have an IP, QID, assetgroup property(ies) to Get-VulnerableHost
   
    .EXAMPLE
    C:\PS> Get-VulnerableHost -ip "128.206.14.92,128.206.14.95,128.206.12.57" -QID "105489" -credential $cred

    .EXAMPLE
    C:\PS> Get-VulnerableHost -assetgroup "MU AS DC Assets (DC)" -QID "105489" -credential $cred

    .EXAMPLE
    C:\PS> $custompsobject | Get-VulnerableHost -credential $cred
           $custompsobject has two properties - IP and QID

    #>

    $vulnhostobject = @()
    $ipaddresses = @()
    $notificationData = @()
    $vulnerableHostInfo = @()
    $assetgroupinfo = @()
    $results = @()
    $vulnhost = @()
    $assetgroup = @()
    $businessunitinfo = @()
    $assetgroupinfo = @()

    #each of these XML files are generated every night or a set amount of time.
    $businessunitinfo = Import-Clixml -Path C:\users\rickardj\Desktop\QualysData\businessunitinfo.xml
    $assetgroupinfo = Import-Clixml -Path C:\users\rickardj\Desktop\QualysData\assetgroupinfo.xml

    $vulnerableHostInfo = Get-VulnerableHost -assetgroup "All" -QID $QID -credential $credential
    $knowledgeBaseInfo = Get-KnowledgebaseInfo -QID $QID -credential $credential

    foreach ($vulnhost in $vulnerableHostInfo){
        foreach ($assetgroup in $assetgroupinfo){
            for ($a=0;$a -lt ($vulnhost.assetgroup).count;$a++){
                for ($b=0;$b -lt ($assetgroup.assetgrouptitle).count;$b++){
                    if ($vulnhost.assetgroup[$a] -eq $assetgroup[$b].assetgrouptitle){
                        for ($u=0; $u -le $($businessunitinfo.userlogin).count;$u++){
                            if ($assetgroup[$b].userlogin -eq $businessunitinfo[$u].userlogin){                        
                                if ($assetgroup[$b].userrole -eq "Unit Manager"){
                                   

                                            $props = @{businessunitinfo=@{businessunit=$businessunitinfo[$u].businessunit
                                                                            userlogin=$businessunitinfo[$u].userlogin
                                                                            firstname=$businessunitinfo[$u].firstname
                                                                            lastname=$businessunitinfo[$u].lastname
                                                                            title=$businessunitinfo[$u].title
                                                                            email=$businessunitinfo[$u].email
                                                                            userrole=$businessunitinfo[$u].userrole
                                                                            assetgroupinfo=@{userlogin=$assetgroup[$b].userlogin
                                                                                             userrole=$assetgroup[$b].userrole
                                                                                             assetgrouptitle=$assetgroup[$b].assetgrouptitle
                                                                                             ip=$assetgroup[$b].ip
                                                                                             vulnerablehost=@{vulnhost=$vulnhost}
                                                                                            }
                                                                            }
                                                       QualysKBInfo=$knowledgeBaseInfo
                                                       }
                    
                                                $temphostobject = New-Object PSObject -Property $props
                                                $vulnhostobject += $temphostobject
                                            
                                                        
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return $vulnhostobject
 }
      
    #  return $notificationData
     # write-host "notificationdata: "$notificationData

      <#

        foreach ($item in $assetgroupinfo){
            for ($u=0; $u -le $($businessunitinfo.userlogin).count;$u++){
                if ($($item.userlogin) -eq $businessunitinfo[$u].userlogin){
                    if ($item.userrole -eq "Unit Manager"){

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

      #>
