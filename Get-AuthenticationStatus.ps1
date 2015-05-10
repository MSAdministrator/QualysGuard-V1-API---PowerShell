function Get-AuthenticationStatus ()
{
    param (
        [parameter(ParameterSetName="set1")] $ipaddress,
        [parameter(ParameterSetName="set2")] $dnsname,
        [parameter(ParameterSetName="set3")] $netbios,
        [System.Management.Automation.CredentialAttribute()]$credential
          ) 
    <#
    .SYNOPSIS 
    Searches lastest scan data for vulnerability scan QIDs to get the hosts authenticatecd scan status
    This function can be searched by IP, DNS Name, and NETBIOS name.

    .DESCRIPTION
    Query's the API to find specific QIDs related to QualysGuard scanning
    Takes input as string.  Reference your search terms by passing the appropriate parameter

    .PARAMETER ipaddress
    Specifices the ipaddress you are wanting authentication information for

    .PARAMETER dnsname
    Specifices the dnsname you are wanting authentication information for

    .PARAMETER netbios
    Specifices the netbios you are wanting authentication information for

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE 1
    C:\PS> Get-AuthenticationStatus -ipaddress "192.168.1.45" -credential $cred
    
    .EXAMPLE 25
    C:\PS> Get-AuthenticationStatus -ipaddress $ipaddress -credential $cred

    #>


    $hosturl=''

    if ($ipaddress){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ipaddress&vuln_details=1"   
    }
    
    if ($dnsname){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_dns=$dnsname&vuln_details=1"
        }
    
    if ($netbios){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_netbios=$netbios&vuln_details=1"
        }

    [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential

        #for ($q=1; $q -le 5; $q++){

            foreach ($item in $hostinfo.SelectNodes("/HOST/INFO_GATHERED/SEVERITY_LEVEL_1/VULNINFO/QID")){
            
                [array]$ipqids += $item
                #write-host "ipqid count:" $ipqids.count
            }
        #}
        
        if ($ipqids.count -ne 0){
            for ($i=0;$i -lt $ipqids.count;$i++){

                if ($($ipqids[$i].InnerText) -contains "38307" ){
               
                return "QID #$($ipqids[$i].InnerText): Linux/Unix Successful"
                }
                if ($($ipqids[$i].InnerText) -contains "105053" ){
                
                return "QID #$($ipqids[$i].InnerText): Linux/Unix Failed"
                } 
                if ($($ipqids[$i].InnerText) -contains "105297" ){
                
                return "QID #$($ipqids[$i].InnerText): Linux/Unix Not Attempted"
                }
                if ($($ipqids[$i].InnerText) -contains "70028" ){
                
                return "QID #$($ipqids[$i].InnerText): Windows Successful"
                }
                if ($($ipqids[$i].InnerText) -contains "105015" ){
                
                return "QID #$($ipqids[$i].InnerText): Windows Failed"
                } 
                if ($($ipqids[$i].InnerText) -contains "105296" ){
                
                return "QID #$($ipqids[$i].InnerText): Windows Not Attempted"
                }
                }
            }
}
