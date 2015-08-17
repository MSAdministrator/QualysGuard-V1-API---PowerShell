﻿    function Get-AssetGroupIPs ()
{
    param (
        [parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1,
                   HelpMessage="Please enter a Asset Group Title")]
        [string[]]$assetgroup,
        
        
        [System.Management.Automation.CredentialAttribute()]$credential
        

            ) 

###### Possibly change all functions to import objects########
#[parameter(Mandatory=$true,
#                   valueFromPipeline=$true)]
#        [object[]] $inputobject,
##############################################################





    <#
    .SYNOPSIS 
    Query's QualysGuard asset_group_list.php for IPs in specific Asset Groups

    .DESCRIPTION
    Query's the API to find All IPs associated with a specific Asset Group(s)
    Takes input as the Asset Group title (string)

    .PARAMETER assetgroup
    Specifices the Asset Group you are wanting information about

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    You can pipe PSCustomObjects that have an IP, dnsname, netbios property(ies) to Get-AssetGroup

    .OUTPUTS
    Returns a list of IPs associated with the specified Asset Group Title

    .EXAMPLE
    C:\PS> Get-AssetGroupIPs -agtitle "MU AS DC Assets (DC)" -credential $cred
    

    #>
          
    [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php?title=$assetgroup" -Credential $credential

    foreach ($item in $hostinfo.SelectNodes("ASSET_GROUP_LIST/ASSET_GROUP/SCANIPS/IP")){
        [array]$agips += $item
    }#End of foreach
        
    if ($agips.count -ne 0){
        for ($i=0;$i -lt $agips.count;$i++){
            write-host "IP #[$i]: $($agips[$i].InnerText)"
        }#End of for loop
    }#End of if
}#Get-AssetGroupIPs
