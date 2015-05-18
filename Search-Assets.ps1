function search-assets ()
{
    param (
        [parameter(ParameterSetName="set1")] $ipaddress,
        [parameter(ParameterSetName="set2")] $assetgroup,
        [parameter(ParameterSetName="set2")] $dnsname,

        
        [System.Management.Automation.CredentialAttribute()]$credential,
        [switch]$hostinfo,
        [switch]$vulnerabilities

            ) 
    <#
    .SYNOPSIS 
    Query's QualysGuard get_host_info.php for a specific host information

    .DESCRIPTION
    Query's the API to find details about a specific host(s)
    Takes input as an IP

    .PARAMETER ScanReference
    Specifices the IP you are wanting information about

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> get-specificscandata "128.206.13.77"
    

    #>

    if ($ipaddress){
        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_ips=$ipaddress"  
        }
    
    if ($assetgroup){
        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_asset_groups=$assetgroup"
        }

    if ($dnsname){
        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_asset_groups=All&dns=begin:$dnsname"
        }          

        $hosturl
    
        [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential
        $hostinfo.ASSET_SEARCH_REPORT
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.IP
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.DNS
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.NETBIOS
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.OPERATING_SYSTEM
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.ASSET_GROUPS.ASSET_GROUP_TITLE
        $hostinfo.ASSET_SEARCH_REPORT.HOST_LIST.HOST.LAST_SCAN_DATE



         foreach ($item in $hostinfo.SelectNodes("ASSET_GROUP_LIST/ASSET_GROUP/SCANIPS/IP")){
            [array]$agips += $item
        }
        
        if ($agips.count -ne 0){
            for ($i=0;$i -lt $agips.count;$i++){
                write-host "IP '#'[$i]: $($agips[$i].InnerText)"
                }
            }


}
