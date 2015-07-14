function Get-VulnerableHosts ()
{
    param (
        [parameter(ParameterSetName="set1",
                   HelpMessage="Please enter a single IP or a range of IPs")]
                   [ValidateNotNullOrEmpty()]
                   [string[]]$targetip,

        [parameter(ParameterSetName="set2",
                   HelpMessage="Please enter an Asset Group or comma seperated list of Asset Groups. Default is All")]
                   [ValidateNotNullOrEmpty()] 
                   [string]$targetag,
        
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
          
    $vulnhostobject = @()
    $hosturl = @()
    $hostinfo = @()
    $assetinfo = @()

    if ($targetip){
            $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_ips=$targetip&vuln_qid=$QID"
        }
    
    if ($targetag){
        if($targetag -eq ""){
            $targetag = "All"
            }

        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_asset_groups=$targetag&vuln_qid=$QID"
        }
        
  
    #this loop will iterate through all the hosturl arrays

       
      #$hosturl
        [xml]$assetinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential

       #$hostinfo | Select-Object -Property *

        #for ($q=1; $q -le 5; $q++){

       
        
         foreach ($item in $assetinfo.SelectNodes("/ASSET_SEARCH_REPORT/HOST_LIST/HOST")){
            $temphostobject = @()
           # $assetgroup += $item.ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
           # write-host "assetgroup "
           # $assetgroup  -join ','
          #  pause  

                #if ($assetgroup -ne ""){
                 #   for ($z=0;$z -lt $assetgroup.count;$z++){
                 #   write-host "Asset Group: " $assetgroup[$z]
                 #   }
                #}

            #TESTING OUT CREATING A NEW OBJECT
            $objectproperties = @{ipaddress=$($item.IP);dnsname=$($item.DNS.InnerText);ostype=$($item.OPERATING_SYSTEM.InnerText);QID=$($QID);lastscandate=$($item.LAST_SCAN_DATE);assetgroup=$($item.ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText)}

            $temphostobject = New-Object PSObject -Property $objectproperties
            $vulnhostobject += $temphostobject
            
            #TESTING OUT CREATING A NEW OBJECT
            [array]$hostinfo += $item
        }

       # write-host "vulnhostobject " $vulnhostobject 
        write-host "vulnhostobject | gm"
        $vulnhostobject | gm
        #$vulnhostobject.assetgroup

        $p=0

       # write-host "hostinfo | gm"
       # $hostinfo | gm

            $hostinfo.count
       
            for ($i=0;$i -lt $hostinfo.count;$i++){
               
                write-host "IP: $($hostinfo[$i].IP)"
                write-host "DNS: `t$($hostinfo[$i].DNS.InnerText)"
                write-host "OS: `t$($hostinfo[$i].OPERATING_SYSTEM.InnerText)"
                write-host "NETBIOS: `t$($hostinfo[$i].NETBIOS.InnerText)"
                
                #$object = New-Object -TypeName PSObject
                #$object | Add-Member -MemberType NoteProperty -Name ipaddress -Value $($hostinfo[$i].IP)
                #$object | Add-Member -MemberType NoteProperty -Name dnsname -Value $($hostinfo[$i].DNS.InnerText)
                #object | Add-Member -MemberType NoteProperty -Name ostype -Value $($hostinfo[$i].OPERATING_SYSTEM.InnerText)
                #$object | Add-Member -MemberType NoteProperty -Name ports -Value $($hostinfo[$i].PORT_SERVICE_LIST.PORT_SERVICE.PORT.InnerText)
                #$object | Add-Member -MemberType NoteProperty -Name services -Value $($hostinfo[$i].PORT_SERVICE_LIST.PORT_SERVICE.SERVICE.InnerText)
                #$object | Add-Member -MemberType NoteProperty -Name QID -Value $($QID)
                #$object | Add-Member -MemberType NoteProperty -Name lastscandate -Value $($hostinfo[$i].LAST_SCAN_DATE)
                #$object | Add-Member -MemberType NoteProperty -Name primarycontact -Value 
             

                #write-host "Asset Group: " $host[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                [array]$assetgroup += $hostinfo[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                
                if ($assetgroup -ne ""){
                    for ($z=0;$z -lt $assetgroup.count;$z++){
                    write-host "Asset Group: " $assetgroup[$z]
                    #$object | Add-Member -MemberType NoteProperty -Name primarycontact -Value (Get-AssetGroupUser -assetgroup $assetgroup[$z] -credential $credential)
                    #$object | Add-Member -MemberType NoteProperty -Name secondarycontact -Value (Get-AssetGroupUser -assetgroup $assetgroup[$z] -credential $credential)
                    }
                }
                
               # $authstatus = Get-AuthenticationStatus -ipaddress "$($hostinfo[$i].IP)" -credential $credential
               # write-host "Authentication Status: " $authstatus
               # Write-Host "________________________________________________________________________________"
                
                $assetgroup = @()
                
                #if ($p -eq 5){
                #    pause
               #     $p=0
               # }
                $p++

              #  for ($q=0;$q -lt $host[$i].ASSET_GROUPS.InnerText;$q++){
               #     [array]$assetgroups += $host[$i].ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText
                #    write-host "Asset Groups Array: " $assetgroups[$q]
                    
                 #   }               

}
    #$object = New-Object -TypeName PSObject -Property $vulnhostobject
    return $vulnhostobject

               }
            