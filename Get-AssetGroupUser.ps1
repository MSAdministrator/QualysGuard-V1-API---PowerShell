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

          
    $assetgroup
    [xml]$hostinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php" -Credential $credential
    
    foreach ($item in $hostinfo.SelectNodes("/ASSET_GROUP_LIST/ASSET_GROUP")){
        #$item.TITLE
        [array]$aglist += $item
        }
   # $aglist | Select-Object -Property *

    for ($i=0;$i -lt $aglist.count;$i++){

        if ($assetgroup -eq $aglist[$i].TITLE.InnerText){
            [array]$aguserlogin += $aglist[$i].ASSIGNED_USERS.ASSIGNED_USER.LOGIN.InnerText
            [array]$aguserfname += $aglist[$i].ASSIGNED_USERS.ASSIGNED_USER.FIRSTNAME.InnerText
            [array]$aguserlname += $aglist[$i].ASSIGNED_USERS.ASSIGNED_USER.LASTNAME.InnerText
            [array]$aguserrole += $aglist[$i].ASSIGNED_USERS.ASSIGNED_USER.ROLE.InnerText

                if ($aguserlogin -ne ""){
                    for ($a=0;$a -lt $aguserlogin.count;$a++){
                        $($aguserlogin[$a] + " " + $aguserfname[$a] + " " + $aguserlname[$a] + " " + $aguserrole[$a])
                        $returnvalue += $($aguserlogin[$a] + " " + $aguserfname[$a] + " " + $aguserlname[$a] + " " + $aguserrole[$a])
                    }
                }
            


        }       
    }
    return $returnvalue
}
