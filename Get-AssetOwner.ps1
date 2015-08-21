function Get-AssetOwner ()
{
    param (
        [parameter(ParameterSetName="set1")][string[]]$ipaddress,
        [parameter(ParameterSetName="set2")][string[]]$dnsname,
        [parameter(ParameterSetName="set3")][string[]]$netbios,
        [System.Management.Automation.CredentialAttribute()]$credential
            ) 
    <#
    .SYNOPSIS 
    Query's QualysGuard get_host_info.php for the owners associated with this asset

    .DESCRIPTION
    Query's the API to find the owner(s) for specific host(s)
    Takes input as an IP, DNS, and NETBIOS

    .PARAMETER ipaddress
    Specificy IPs you are wanting to know the owner of
    You can pass multiple IPs in a comma seperated list

    .PARAMETER dnsname
    Specify DNS Names you are wanting to know the owner of
    You can pass multiple DNS Names in a comma seperated list

    .PARAMETER netbios
    Specify NETBIOS names you are wanting to know the owner of
    You can pass multiple NETBIOS names in a comma seperated list

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> get-specificscandata "128.206.13.77"
    

    #>

    $hosturl = @()
    if ($ipaddress){
        for ($i=0;$i -lt $ipaddress.count;$i++){
            $hosturl += $("https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=" + ($ipaddress)[$i] + "&general_info=1")
            }
        }
    
    if ($dnsname){
        for ($i=0;$i -lt $dnsname.count;$i++){
            $hosturl += "https://qualysapi.qualys.com/msp/get_host_info.php?host_dns=" + ($dnsname)[$i] + "&general_info=1"
            }
        }
        
    if ($netbios){
        for ($i=0;$i -lt $netbios.count;$i++){
            $hosturl += "https://qualysapi.qualys.com/msp/get_host_info.php?host_netbios=" + ($netbios)[$i] + "&general_info=1"
            }
        }
    #this loop will iterate through all the hosturl arrays
   
    for ($h=0;$h -lt $hosturl.count;$h++){       

 

    
    [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl[$h] -Credential $credential
    
    if ($hostinfo.HOST.ERROR){
        write-host "ERROR NUMBER " $hostinfo.HOST.ERROR.number
        write-host $hostinfo.HOST.ERROR.'#text'
        }

   

    foreach ($item in $hostinfo.SelectNodes("/HOST")){
        [array]$owner += $item.OWNER.USER
        [array]$user += $item.USER_LIST.USER


        $objectproperties = @{ownerfname=$($item.OWNER.USER.FIRSTNAME.InnerText);
                              ownerlname=$($item.OWNER.USER.LASTNAME.InnerText);
                              ownerlogin=$($item.OWNER.USER.USER_LOGIN.InnerText)
                              }

        $temphostobject = New-Object PSObject -Property $objectproperties

        }
        
  #  for ($o=0;$o -lt $owner.count;$o++){
  #      Write-Host "Owner: "$($owner[$o].FIRSTNAME.InnerText)$($owner[$o].LASTNAME.InnerText)$($owner[$o].USER_LOGIN.InnerText)
  #      }    
  #  for ($a=0;$a -lt $user.count;$a++){
  #      write-host "User: "$($user[$a].FIRSTNAME.InnerText)$($user[$a].LASTNAME.InnerText)$($user[$a].USER_LOGIN.InnerText)

 #   }
    }#end of hosturl for loop
    return $
}