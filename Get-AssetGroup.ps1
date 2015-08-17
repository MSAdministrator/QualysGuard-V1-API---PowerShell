function Get-AssetGroup ()
{

[cmdletbinding()]
    param (
        [parameter(ParameterSetName="set1",
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter a single IP or a range of IPs")]
                   [ValidateNotNullOrEmpty()]
                   [string[]]$ip,

        [parameter(ParameterSetName="set2",
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter an DNS Name or comma seperated list of DNS Names.")]
                   [ValidateNotNullOrEmpty()] 
                   [string[]]$dnsname,

         [parameter(ParameterSetName="set3",
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter an NetBios Name or comma seperated list of NetBios Names.")]
                   [ValidateNotNullOrEmpty()] 
                   [string[]]$netbios,
        
        [parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please provide a credential obejct")]
                   [ValidateNotNullOrEmpty()]
                   [System.Management.Automation.CredentialAttribute()]$credential
        ) 

    <#
    .SYNOPSIS 
    Query's QualysGuard get_host_info.php for a host or hosts and find the Asset Groups associated with it

    .DESCRIPTION
    Query's the API to find the Asset Groups associated with the specific host
    Takes input as an IP(s), DNS Name, and NetBios name

    .PARAMETER ip
    Specify a single or a comma seperated list of IP addresses you are wanting to find Asset Groups for

    .PARAMETER dnsname
    Specifices a single or a comma seperated list of DNS Names you are wanting to find Asset Groups for

    .PARAMETER netbios
    Specifices a single or a comma seperated list of netbios names you are wanting to find Asset Groups for

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    You can pipe PSCustomObjects that have an IP, dnsname, netbios property(ies) to Get-AssetGroup
   
    .EXAMPLE
    C:\PS> Get-AssetGroup -ip "128.206.14.92,128.206.14.95,128.206.12.57" -credential $cred

    .EXAMPLE
    C:\PS> Get-AssetGroup -dnsname "ksc.col.missouri.edu" -credential $cred

    .EXAMPLE
    C:\PS> Get-AssetGroup -netbios "ksc" -credential $cred

    .EXAMPLE
    C:\PS> $custompsobject | Get-AssetGroup -credential $cred
           $custompsobject has a property of IP

    #>

$hosturl = @()

    if ($ip){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_ip=$ip&general_info=1"  
        }
    
    if ($dnsname){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_dns=$dnsname&general_info=1"
        }
        
    if ($netbios){
        $hosturl = "https://qualysapi.qualys.com/msp/get_host_info.php?host_netbios=$netbios&general_info=1"
        }

    write-host "IP: " $ip

    write-host "hosturl: " $hosturl
    [xml]$hostinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential
    write-host "hostinfo: " $hostinfo

    foreach ($item in $hostinfo.SelectNodes("/HOST")){
        [array]$assetgroup += $item.ASSET_GROUP_LIST.ASSET_GROUP.ASSET_GROUP_TITLE
        write-host $item.ASSET_GROUP_LIST.ASSET_GROUP.ASSET_GROUP_TITLE
        }      
}