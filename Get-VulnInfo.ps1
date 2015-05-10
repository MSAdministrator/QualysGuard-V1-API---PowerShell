function Get-VulnInfo ()
{
    param (
        [parameter(Mandatory=$true,Position=1,HelpMessage="Please enter an IP Address")]
        [string]$ipaddress,
        [System.Management.Automation.CredentialAttribute()]$credential
            ) 
    <#
    .SYNOPSIS 
    Query's QualysGuard asset_group_list.php for IPs in specific Asset Groups

    .DESCRIPTION
    Query's the API to find details about a specific Asset Group(s)
    Takes input as the Asset Group title (string)

    .PARAMETER ScanReference
    Specifices the Asset Group you are wanting information about

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> Get-AssetGroupIPs -agtitle "MU AS DC Assets (DC)" -credential $cred
    

    #>
          

       
      
        [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&vuln_details=1" -Credential $credential

        
     #   $hostinfo.ASSET_DATA_REPORT.HOST_LIST.HOST | Select-Object -Property *

    

        $hostinfo = $hostinfo.SelectNodes("/HOST")
        #iterate through INFO_GATHERED, Potential Vuln, & confirmed vulns
        #iterate through each severity level (1-5)
        #get QID, Level, Title, etc.
        #xport to CSV


        for ($q=1; $q -le 5; $q++){

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/QID")){
            
            [array]$ipvulnqids += $item
        }

        foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/SEVERITY_LEVEL")){
            
            [array]$ipsevlevel += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/TITLE")){
            
            [array]$ipsevtitle += $item
        }

        foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/New")){
            
            [array]$ipsevnew += $item
        }

        foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/Re-Opened")){
            
            [array]$ipsevreopened += $item
        }

        foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/Fixed")){
            
            [array]$ipsevfixed += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/CATEGORY")){
            
            [array]$ipsevcategory += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/PORT")){
            
            [array]$ipsevport += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/SERVICE")){
            
            [array]$ipsevservice += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/FIRST_FOUND")){
            
            [array]$ipsevfirstfound += $item
        }


         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/LAST_FOUND")){
            
            [array]$ipsevlastfound += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/TIMES_FOUND")){
            
            [array]$ipsevtimesfound += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/DIAGNOSIS")){
            
            [array]$ipsevdiagnosis += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/CONSEQUENCE")){
            
            [array]$ipsevconsequence += $item
        }

         foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_$q/VULNINFO/SOLUTION")){
            
            [array]$ipsevsolution += $item
        }



        }
        

       #if ($ipqids.count -ne 0){
            for ($i=0;$i -lt $ipvulnqids.count;$i++){
                write-host "QID: `t$($ipvulnqids[$i].InnerText)"
            }

            for ($i=0;$i -lt $ipsevlevel.count;$i++){
                write-host "Severity Level: `t$($ipsevlevel[$i].InnerText)"
            }
            for ($i=0;$i -lt $ipsevtitle.count;$i++){
                write-host "Title: `t$($ipsevtitle[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevnew.count;$i++){
                write-host "Status:  `t$($ipsevnew[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevreopened.count;$i++){
                write-host "Status: `t$($ipsevreopened[$i].InnerText)"
            } 
                
            for ($i=0;$i -lt $ipsevfixed.count;$i++){
                write-host "Status: `t$($ipsevfixed[$i].InnerText)"
            } 
            
            for ($i=0;$i -lt $ipsevcategory.count;$i++){
                write-host "Category: `t$($ipsevcategory[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevport.count;$i++){
                write-host "Port: `t$($ipsevport[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevservice.count;$i++){
                write-host "Service: `t$($ipsevservice[$i].InnerText)"
            } 
                
            for ($i=0;$i -lt $ipsevfirstfound.count;$i++){
                write-host "First Found Date: `t$($ipsevfirstfound[$i].InnerText)"
            }

            for ($i=0;$i -lt $ipsevlastfound.count;$i++){
                write-host "Last Found Date: `t$($ipsevlastfound[$i].InnerText)"
            } 
            

            for ($i=0;$i -lt $ipsevtimesfound.count;$i++){
                write-host "Times Found: `t$($ipsevtimesfound[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevdiagnosis.count;$i++){
                write-host "Diagnosis: `t$($ipsevdiagnosis[$i].InnerText)"
            }
               
            for ($i=0;$i -lt $ipsevconsequence.count;$i++){
                write-host "Consequence: `t$($ipsevconsequence[$i].InnerText)"
            } 
                
            for ($i=0;$i -lt $ipsevsolution.count;$i++){
                write-host "Solution: `t$($ipsevsolution[$i].InnerText)"
            }

            }