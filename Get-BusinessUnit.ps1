function Get-BusinessUnit ()
{
    param (
        [parameter(ParameterSetName="set1")] $ipaddress,
        [parameter(ParameterSetName="set2")] $dnsname,
        [parameter(ParameterSetName="set3")] $netbios,
        [System.Management.Automation.CredentialAttribute()]$credential
            ) 
    <#
    .SYNOPSIS 
    Query's QualysGuard get_host_info.php for the assets business units

    .DESCRIPTION
    Query's the API to find the business unit for specific host(s)
    Takes input as an IP

    .PARAMETER 

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> get-specificscandata "128.206.13.77"
    

    #>

    if ($ipaddress){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&general_info=1"  
        }
    
    if ($dnsname){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_dns=$dnsname&general_info=1"
        }
        
    if ($netbios){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_netbios=$netbios&general_info=1"
        }

          
    
    [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential
    
    foreach ($item in $hostinfo.SelectNodes("/HOST/BUSINESS_UNIT_LIST/BUSINESS_UNIT")){
            
                [array]$businessunit += $item
                $businessunit.InnerText
               # write-host "business unit count:" $businessunit.count
            }
            #tezs
}