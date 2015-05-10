 foreach ($item in $hostinfo.SelectNodes("HOST/IP")){
            [array]$qualysips += $item
        }

        for ($i=0;$i -lt $qualysips.count;$i++){
            write-host "IP: `t`t`t`t`t`t`t$($qualysips[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportip = $($qualysips[$i].InnerText)
                }
                
            }

        foreach ($item in $hostinfo.SelectNodes("HOST/DNS")){
            [array]$dns += $item
        }

        for ($i=0;$i -lt $dns.count;$i++){
            write-host "DNS: `t`t`t`t`t`t`t$($dns[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportdns = $($dns[$i].InnerText)
                }
            }

        foreach ($item in $hostinfo.SelectNodes("HOST/NETBIOS")){
            [array]$netbios += $item
        }

        for ($i=0;$i -lt $netbios.count;$i++){
            write-host "NETBIOS: `t`t`t`t`t`t$($netbios[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportnetbios = $($netbios[$i].InnerText)
                }
            }


        foreach ($item in $hostinfo.SelectNodes("HOST/OPERATING_SYSTEM")){
            [array]$os += $item
        }

        for ($i=0;$i -lt $os.count;$i++){
            write-host "Operating System: `t`t`t`t$($os[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportos = $($os[$i].InnerText)
                }
            }
        
        foreach ($item in $hostinfo.SelectNodes("HOST/LAST_SCAN_DATE")){
            [array]$lastscandate += $item
        }

        for ($i=0;$i -lt $lastscandate.count;$i++){
            write-host "Last Scan Date: `t`t`t`t$($lastscandate[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportlastscandate = $($lastscandate[$i].InnerText)
                }
            }

        foreach ($item in $hostinfo.SelectNodes("HOST/USER_LIST/USER/FIRSTNAME")){
            [array]$fname += $item
        }
              

         foreach ($item in $hostinfo.SelectNodes("HOST/USER_LIST/USER/LASTNAME")){
            [array]$lname += $item
        }

        for ($i=0;$i -lt $lname.count;$i++){
            write-host "User: `t`t`t`t`t`t`t$($fname[$i].InnerText) $($lname[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportfname = $($fname[$i].InnerText)
                [string]$exportlname = $($lname[$i].InnerText)
                }
            }

        

        foreach ($item in $hostinfo.SelectNodes("HOST/ASSET_GROUP_LIST/ASSET_GROUP/ASSET_GROUP_TITLE")){
            [array]$assetgroups += $item
        }

        
        foreach ($item in $hostinfo.SelectNodes("HOST/BUSINESS_UNIT_LIST/BUSINESS_UNIT")){
            [array]$busunits += $item
        }
       
        for ($i=0;$i -lt $assetgroups.count;$i++){
            write-host "Asset Group: `t`t`t`t`t$($assetgroups[$i].InnerText)"
            if ($exportcsv -eq $true){
                [string]$exportag = $($assetgroups[$i].InnerText)
                }
            }

        for ($i=0;$i -lt $busunits.count;$i++){
                write-host "Business Unit: `t`t`t`t`t$($busunits[$i].InnerText)"
                if ($exportcsv -eq $true){
                [string]$exportbusunit = $($busunits[$i].InnerText)
                }
        }
        
           foreach ($item in $hostinfo.SelectNodes("HOST/AUTHENTICATION_RECORD_LIST/AUTH_WINDOWS")){
            [array]$windowsauth += $item
        }

        if ($windowsauth.count -ne 0){
            for ($i=0;$i -lt $windowsauth.count;$i++){
                write-host "Windows Authentication Record: `t$($windowsauth[$i].InnerText)"
                $authstatus = Get-AuthenticationStatus -ipaddress $ipaddress -credential $credential
                write-host "Windows Authentication Status: `t$authstatus"
                }
            }
       
           foreach ($item in $hostinfo.SelectNodes("HOST/AUTHENTICATION_RECORD_LIST/AUTH_UNIX")){
            [array]$unixsauth += $item
            #write-host "Unix Auth Count:" $unixsauth.count
        }

        if ($unixsauth.count -ne 0){
            for ($i=0;$i -lt $unixsauth.count;$i++){
            
                write-host "Unix Authentication Record: `t$($unixsauth[$i].InnerText)"
                $authstatus = Get-AuthenticationStatus -ipaddress $ipaddress -credential $credential
                write-host "Linux/Unix Authentication Status: `t$authstatus"
                }
            }




           
     if ($exportcsv -eq $true){
        "$exportip,$exportdns,$exportnetbios,$exportos,$exportlastscandate,$exportfname,$exportlname,$exportag,$exportbusunit" > C:\Users\JAR\Desktop\test.txt


     }


       

        }
    #[xml]$hostvulninfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&vuln_details=1" -Credential $credential

    if ($services -eq $true){

        
        
        }
    if ($vulnerabilities -eq $true){$scanreportdetails.SCAN.IP.vulns.cat.vuln}

    #$scanreportdetails.SCAN.IP.services.cat | Select-Object -Property * -ExcludeProperty InnerXML,OuterXML,InnerText
    Write-Host $scanreportdetails.SCAN.IP.value -ForegroundColor Cyan

  #  foreach ($scannedhost in $scanreportdetails){
        

   # }




