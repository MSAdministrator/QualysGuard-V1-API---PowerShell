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

    . "Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\Invoke-Parallel.ps1"
    $Throttle = 5 #threads
  
    #empty array used for runspacecollection
    $RunspaceCollection = @()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1,$Throttle)
    $RunspacePool.Open()

    $vulnhostobject = @()
    $ipaddresses = @()
    $notificationData = @()
    $vulnerableHostInfo = @()
    $assetgroupinfo = @()
    $results = @()
  
    #each of these XML files are generated every night or a set amount of time.
    $businessunitinfo = Import-Clixml -Path C:\users\rickardj\Desktop\QualysData\businessunitinfo.xml
    $assetgroupinfo = Import-Clixml -Path C:\users\rickardj\Desktop\QualysData\assetgroupinfo.xml

    $vulnerableHostInfo = Get-VulnerableHost -assetgroup "All" -QID $QID -credential $credential
    
    foreach ($vulnhost in $vulnerableHostInfo){
        foreach ($assetgroup in $assetgroupinfo){
            for ($a=0;$a -lt ($vulnhost.assetgroup).count;$a++){
                for ($b=0;$b -lt ($assetgroup.assetgrouptitle).count;$a++){
                    write-host "vulnhost.assetgroup[$a]: "$vulnhost.assetgroup[$a]
                    write-host "assetgroup.assetgrouptitle: "$assetgroup[$b].assetgrouptitle
                    if ($vulnhost.assetgroup[$a] -eq $assetgroup[$b].assetgrouptitle]){
                        for ($u=0; $u -le $($businessunitinfo.userlogin).count;$u++){
                                write-host "assetgroup.userlogin: "$assetgroup.userlogin
                                write-host "busiunessunitinfo[$u].userlogin: "$businessunitinfo[$u].userlogin
                            if ($assetgroup[$b].userlogin -eq $businessunitinfo[$u].userlogin){                        
                                if ($assetgroup[$b].userrole -eq "Unit Manager"){
                                

                                $props = @{businessunitinfo = @{businessunit=$businessunitinfo[$u].businessunit
                                                                userlogin=$businessunitinfo[$u].userlogin
                                                                firstname=$businessunitinfo[$u].firstname
                                                                lastname=$businessunitinfo[$u].lastname
                                                                title=$businessunitinfo[$u].title
                                                                email=$businessunitinfo[$u].email
                                                                userrole=$businessunitinfo[$u].userrole
                                                                }
                                           assetgroupinfo= @{userlogin=$assetgroup[$b].userlogin
                                                             userrole=$assetgroup[$b].userrole
                                                             assetgrouptitle=$assetgroup[$b].assetgrouptitle
                                                             ip=$assetgroup[$b].ip
                                                            }
                                           vulnerablehost=$vulnhost
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

                    $invokeParallelObj = New-Object PSObject -Property @{QID=$QID
                                                                         credential=$credential
                                                                        }
                                
                    

                 
                   $notificationData = Invoke-Parallel -InputObject $assetgroupIPs -Parameter $invokeParallelObj -Throttle 5 -ScriptBlock {
                        $ipaddress = $_
                        write-host "ipaddress: "$ipaddress
                        $credential = $parameter.credential
                        write-host "credential: "$credential
                        $QID = $parameter.QID
                        write-host "QID: " $QID
 ################################################################################################################################################################################                       

                        $hosturl = @()
	                    $vulnobject = @()
	                    $potentialvulnobject = @()
	                    $infogatheredvulnobject = @()
	
	                    $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&general_info=1&vuln_details=1"
	                    $hosturl
	                    [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential
	
	                    foreach ($thing in $hostinfo.SelectNodes("/HOST"))
	                    {
                            for ($s = 1; $s -le 3; $s++) {
			                    switch ($s) {
				                    1 {
					                    $vulntype = "VULNS"
					                    $vulnTypeDataTable = $datagridviewVuln
				                    }
				                    2 {
					                    $vulntype = "POTENTIAL_VULNS"
					                    $vulnTypeDataTable = $datagridviewPotential
				                    }
				                    3 {
					                    $vulntype = "INFO_GATHERED"
					                    $vulnTypeDataTable = $datagridviewInfoGathered
				                    }
			                    }
			
			                    for ($x = 1; $x -le 5; $x++) {
				                    $xpath = ("//{0}/SEVERITY_LEVEL_{1}/VULNINFO" -f $vulntype,$x)
				                    foreach ($vuln in $thing.SelectNodes($xpath)) {
					
                                        if ($vuln.QID.InnerText -eq $QID){

                                            for ($a=0;$a -lt $($thing.ASSET_GROUP_LIST.ASSET_GROUP.InnerText).count;$a++){

					                            $obj = New-Object System.Management.Automation.PSObject
					
					                            $obj | Add-Member -MemberType NoteProperty -Name "IPADDRESS" -Value $thing.IP | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "DNSNAME" -Value $thing.DNS.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "NETBIOS" -Value $thing.NETBIOS.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "OPERATING_SYSTEM" -Value $thing.OPERATING_SYSTEM.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "LASTSCANDATE" -Value $thing.LAST_SCAN_DATE | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "FIRSTNAME" -Value $thing.OWNER.USER.FIRSTNAME.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "LASTNAME" -Value $thing.OWNER.USER.LASTNAME.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "LOGIN" -Value $thing.OWNER.USER.USER_LOGIN.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "ASSETGROUP" -Value $thing.ASSET_GROUP_LIST.ASSET_GROUP[$a].InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "BUSINESSUNIT" -Value $thing.OWNER.USER.USER_LOGIN.InnerText | Out-String
					
					                            $obj | Add-Member -MemberType NoteProperty -Name "QID" -Value $vuln.QID.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "SEVERITYLEVEL" -Value $vuln.SEVERITY_LEVEL.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "TITLE" -Value $vuln.TITLE.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "VULN_STATUS" -Value $vuln.VULN_STATUS.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "CATEGORY" -Value $vuln.CATEGORY.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "PORT" -Value $vuln.PORT.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "SERVICE" -Value $vuln.SERVICE.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "PROTOCOL" -Value $vuln.PROTOCOL.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "FIRST_FOUND" -Value $vuln.FIRST_FOUND.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "LAST_FOUND" -Value $vuln.LAST_FOUND.InnerText | Out-String
					                            $obj | Add-Member -MemberType NoteProperty -Name "TIMES_FOUND" -Value $vuln.TIMES_FOUND.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "VENDORREF" -Value $vuln.VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "CVE" -Value $vuln.CVE_ID_LIST.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "VULNIMPACT" -Value $vuln.CONSEQUENCE.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "SOLUTION" -Value $vuln.SOLUTION.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "COMPLIANCE" -Value $vuln.COMPLIANCE.COMPLIANCE_INFO.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "EXPLOITABILITY" -Value $vuln.CORRELATION.EXPLOITABILITY.InnerText | Out-String
                                                $obj | Add-Member -MemberType NoteProperty -Name "MALWARE" -Value $vuln.CORRELATION.MALWARE.InnerText | Out-String
                   
					
					                        $vulnobject += $obj
                                        }
                                        }
				                    }#end of foreach
			                    }#end of for loop for vulnerabilities DataTable
		                    }#end of for loop to set items based on switch statement
                        }
                        return $vulnobject




 ################################################################################################################################################################################ 
                    }
                        $props = @{
                                    userlogin=$item.userlogin
                                    userrole=$item.userrole
                                    ipaddress=$item.ip
                                    vulndata=$notificationData
                                    QID=$QID
                                }
                                

                                $tempNotificationResults = New-Object PSObject -Property $props

                                $results += $tempNotificationResults



                              # return $vulnobject
               #     }#END OF FOR LOOP BEFORE GETTING NOTIFICATION DATA
          #  }#END OF TEMPNOTIFICATION DATA SRIPT
                                
                                
                            }
                             
                    }
                    
                }
                
       
    



    
    }#end of foreach-parrellel
    return $results
 # return $notificationData#>
}