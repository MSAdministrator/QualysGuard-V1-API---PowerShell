function Get-VulnerableHosts ()
{
    param (
        [parameter(Mandatory=$true,Position=1,HelpMessage="Please enter an IP Address")]
        [string]$QID,
        [parameter(Position=2,HelpMessage="Please enter the Scope of your Search.  Default is All.")]
        [string]$searchscope,
        [System.Management.Automation.CredentialAttribute()]$credential
        ) 
    
    If ($searchscope -eq "") {$searchscope = "All"}

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
          

       
      
        [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_search.php?target_asset_groups=$searchscope&vuln_qid=$QID" -Credential $credential

       #$hostinfo | Select-Object -Property *

        #for ($q=1; $q -le 5; $q++){

         foreach ($item in $hostinfo.SelectNodes("/ASSET_SEARCH_REPORT/HOST_LIST/HOST")){
            
            [array]$host += $item
        }

        
        $p=0

       
            for ($i=0;$i -lt $host.count;$i++){
               
                write-host "IP: $($host[$i].IP)"
                write-host "DNS: `t$($host[$i].DNS.InnerText)"
                write-host "OS: `t$($host[$i].OPERATING_SYSTEM.InnerText)"
                write-host "NETBIOS: `t$($host[$i].NETBIOS.InnerText)"
                
               

                #write-host "Asset Group: " $host[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                [array]$test += $host[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                
                if ($test -ne ""){
                    for ($z=0;$z -lt $test.count;$z++){
                    write-host "Asset Group: " $test[$z]

                    }
                }
                Write-Host "________________________________________________________________________________"
                
                $test = @()
                
                if ($p -eq 5){
                    pause
                    $p=0
                }
                $p++

              #  for ($q=0;$q -lt $host[$i].ASSET_GROUPS.InnerText;$q++){
               #     [array]$assetgroups += $host[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                #    write-host "Asset Groups Array: " $assetgroups[$q]
                    
                 #   }               

}

            }
            