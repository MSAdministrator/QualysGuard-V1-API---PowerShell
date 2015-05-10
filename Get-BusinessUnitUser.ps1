function Get-BusinessUnit ()
{
    param (
        [parameter(ParameterSetName="set1")] $businessunit,
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

          
    
    [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/user_list.php" -Credential $credential
    
    foreach ($item in $hostinfo.SelectNodes("/USER_LIST_OUTPUT/USER_LIST/USER")){
        if ($businessunit -eq $item.BUSINESS_UNIT){
            write-host $item
            }
        }
            
           
            }
           
