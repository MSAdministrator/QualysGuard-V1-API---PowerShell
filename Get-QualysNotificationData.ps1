Function Get-QualysNotificationData ($ipaddress,$QID,$cred) {
	
	$hosturl = @()
	$vulnobject = @()
	$potentialvulnobject = @()
	$infogatheredvulnobject = @()
	
	$hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&general_info=1&vuln_details=1"
	
	[xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $cred
	
	foreach ($item in $hostinfo.SelectNodes("/HOST"))
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
				foreach ($vuln in $item.SelectNodes($xpath)) {
					
                    if ($vuln.QID.InnerText -eq $QID){

                        for ($a=0;$a -lt $($item.ASSET_GROUP_LIST.ASSET_GROUP.InnerText).count;$a++){

					        $obj = New-Object System.Management.Automation.PSObject
					
					        $obj | Add-Member -MemberType NoteProperty -Name "IPADDRESS" -Value $item.IP | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "DNSNAME" -Value $item.DNS.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "NETBIOS" -Value $item.NETBIOS.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "OPERATING_SYSTEM" -Value $item.OPERATING_SYSTEM.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "LASTSCANDATE" -Value $item.LAST_SCAN_DATE | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "FIRSTNAME" -Value $item.OWNER.USER.FIRSTNAME.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "LASTNAME" -Value $item.OWNER.USER.LASTNAME.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "LOGIN" -Value $item.OWNER.USER.USER_LOGIN.InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "ASSETGROUP" -Value $item.ASSET_GROUP_LIST.ASSET_GROUP[$a].InnerText | Out-String
                            $obj | Add-Member -MemberType NoteProperty -Name "BUSINESSUNIT" -Value $item.OWNER.USER.USER_LOGIN.InnerText | Out-String
					
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
}