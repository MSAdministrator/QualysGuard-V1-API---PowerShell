    function Get-AssetGroupIPs ()
{
    param (
        [parameter(Mandatory=$true,Position=1,HelpMessage="Please enter a Asset Group Title")]
        [string]$agtitle,
        
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
          
    
      
        [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php?title=$agtitle" -Credential $credential



         foreach ($item in $hostinfo.SelectNodes("ASSET_GROUP_LIST/ASSET_GROUP/SCANIPS/IP")){
            [array]$agips += $item
        }
        
        if ($agips.count -ne 0){
            for ($i=0;$i -lt $agips.count;$i++){
                write-host "IP #[$i]: $($agips[$i].InnerText)"
                }
            }


}
