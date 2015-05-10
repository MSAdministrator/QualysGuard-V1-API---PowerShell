function Get-AssetGroupUser ()
{
    param (
        [parameter(ParameterSetName="set1")] $assetgroup,
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

          
    
    [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php" -Credential $credential
    
    foreach ($item in $hostinfo.SelectNodes("/ASSET_GROUP_LIST/ASSET_GROUP")){
        if ($assetgroup -eq $item.TITLE){
            write-host $item.ASSIGNED_USERS.ASSIGNED_USER.LOGIN.InnerText
            write-host $item.ASSIGNED_USERS.ASSIGNED_USER.FIRSTNAME.InnerText
            write-host $item.ASSIGNED_USERS.ASSIGNED_USER.LASTNAME.InnerText
            write-host $item.ASSIGNED_USERS.ASSIGNED_USER.ROLE.InnerText
            }
        }
            
                
            
            #tezs
}