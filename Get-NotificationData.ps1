<#
Need to create the inputobject for send-qualysnotification by calling other functions and getting the data together

Our inputobject variable needs the following properties
inputobject.owner
inputobject.assetgroup
inputobject.businessunit
vulntitle
vulnlevel
cve
QID
vendorref
vulnimpact
vulnsolution
exploitability
compliance
malware



it also needs all ips for this owner
ipaddress
dns
hostname
firstdetection
lastdetection
timesdetected



#>

function Get-NotificationData {
[cmdletbinding()]
    param (
        [parameter(ParameterSetName="set1",
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter a single IP or a range of IPs")]
                   [ValidateNotNullOrEmpty()]
                   [string[]]$ipaddress,

        [parameter(ParameterSetName="set2",
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter an Asset Group or comma seperated list of Asset Groups. Default is All")]
                   [ValidateNotNullOrEmpty()] 
                   [string[]]$assetgroup,
        
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
    

    $vulninfo = Get-KnowledgebaseInfo -QID $($QID) -credential $credential
    $vulninfo
    $notificationinfo = Get-VulnerableHost -assetgroup "All" -QID $QID -credential $credential
    $notificationinfo.ipaddress
    foreach ($ip in $notificationinfo.ipaddress){
        $hostinfo += Get-HostInfo -ipaddress $ip -credential $credential
        $hostinfo

    }
    $hostinfo
        
<#

    $vulnobject = @()

  #  $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$($txtBoxIPAddress.Text)&general_info=1&vuln_details=1"
	
	#$[xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $cred
	
	foreach ($item in $hostinfo.SelectNodes("/HOST")){
        $objectproperties = @{ipaddress=$($item.IP);
                              dnsname=$($item.DNS.InnerText);
                              netbios=$($item.NETBIOS.InnerText);
                              ostype=$($item.OPERATING_SYSTEM.InnerText);
                              QID=$($QID);lastscandate=$($item.LAST_SCAN_DATE);
                              assetgroup=$($item.ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText);
                              authrecord = $($item.AUTHENTICATION_RECORD_LIST.InnerText);
		                      comment = $($item.COMMENT.InnerText);
		                      ownerfname = $($item.OWNER.USER.FIRSTNAME.InnerText);
		                      ownerlname = $($item.OWNER.USER.LASTNAME.InnerText);
		                      ownerlogin = $($item.OWNER.USER.USER_LOGIN.InnerText);
		                      businessunit = $($item.BUSINESS_UNIT_LIST.BUSINESS_UNIT.InnerText);
                             }

        [array]$aguserfname = $($item.USER_LIST.USER.FIRSTNAME.InnerText)
        [array]$aguserlname = $($item.USER_LIST.USER.LASTNAME.InnerText)
		
        if ($aguserfname -ne "") {
	        for ($a = 0; $a -lt $aguserfname.count; $a++) {
		        $userlistname += $($aguserfname[$a] + " " + $aguserlname[$a])	
	        }

        $objectproperties += @{userlistname=$($userlistname)}

        }

        $notificationinfo = New-Object PSObject -Property $objectproperties

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
			    foreach ($vuln in $item.SelectNodes($xpath)) {
                    if ($vuln.QID.InnerText -eq $QID){
				        $obj = New-Object System.Management.Automation.PSObject
					
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
				        $obj | Add-Member -MemberType NoteProperty -Name "DIAGNOSIS" -Value $vuln.DIAGNOSIS.InnerText | Out-String
				        $obj | Add-Member -MemberType NoteProperty -Name "SOLUTION" -Value $vuln.SOLUTION.InnerText | Out-String
					
				        $notificationinfo += $obj
                    }#end of if statement
			    }#end of foreach
		    }#end of for loop for vulnerabilities DataTable
	    }#end of for loop to set items based on switch statement

write-host "vulnobject: "$notificationinfo
write-host "vulnobject | select *: " $notificationinfo | select -Property *


    

    foreach ($ip in $notificationinfo.ipaddress){
        $notificationinfo += Get-AssetOwner -ipaddress $ip -credential $credential

    }


}
#>
}
#we first need to get the vulnerability that we are sending an email for
#next we get the scope (i.e. All, certain Asset Group, Business Unit, etc.)

