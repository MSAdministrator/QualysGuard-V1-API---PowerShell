function Get-VulnerableHost ()
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
                   HelpMessage="Please enter an Asset Group or comma seperated list of Asset Groups. Default is All")]
                   [ValidateNotNullOrEmpty()] 
                   [string[]]$assetgroup,
        
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please enter a QID (Qualys ID) to search for")]
                   [ValidateCount(1,20)]
                   [ValidateNotNullOrEmpty()]
                   [string[]]$QID,
        
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please provide a crednetial obejct")]
                   [ValidateNotNullOrEmpty()]
                   [System.Management.Automation.CredentialAttribute()]$credential
        ) 
    
  
    <#
    .SYNOPSIS 
    Query's QualysGuard asset_search.php for a host or  hosts with a specific vulnerability

    .DESCRIPTION
    Query's the API to find details about a specific host
    Takes input as an IP(s), Asset Group title (string), and specific QID (Vulnerability)

    .PARAMETER ip
    Specify a single or a comma seperated list of IP addresses you are wanting to search

    .PARAMETER assetgroup
    Specifices a single or a comma seperated list of Asset Groups you are wanting to search
    Default value is "All"

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    You can pipe PSCustomObjects that have an IP, QID, assetgroup property(ies) to Get-VulnerableHost
   
    .EXAMPLE
    C:\PS> Get-VulnerableHost -ip "128.206.14.92,128.206.14.95,128.206.12.57" -QID "105489" -credential $cred

    .EXAMPLE
    C:\PS> Get-VulnerableHost -assetgroup "MU AS DC Assets (DC)" -QID "105489" -credential $cred

    .EXAMPLE
    C:\PS> $custompsobject | Get-VulnerableHost -credential $cred
           $custompsobject has two properties - IP and QID

    #>

    $vulnhostobject = @()
    $hosturl = @()
    $assetinfo = @()
    $item = @()

    if ($ip){
        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_ips=$ip&vuln_qid=$QID"
    }
    
    if ($assetgroup){
        $hosturl = "https://qualysapi.qualys.com/msp/asset_search.php?target_asset_groups=$assetgroup&vuln_qid=$QID"
    }

    [xml]$assetinfo = Invoke-RestMethod -Uri $hosturl -Credential $credential
      
    foreach ($item in $assetinfo.SelectNodes("/ASSET_SEARCH_REPORT/HOST_LIST/HOST")){
        #CREATING A NEW OBJECT
        $objectproperties = @{ipaddress=$($item.IP);
                              dnsname=$($item.DNS.InnerText);
                              netbios=$($item.NETBIOS.InnerText);
                              ostype=$($item.OPERATING_SYSTEM.InnerText);
                              QID=$($QID);
                              QIDResult=$($item.QID_LIST.$($QID).RESULT.InnerText);
                              lastscandate=$($item.LAST_SCAN_DATE);
                              assetgroup=$($item.ASSET_GROUPS.ASSET_GROUP_TITLE.InnerText)
                              }

        $temphostobject = New-Object PSObject -Property $objectproperties
        $vulnhostobject += $temphostobject
    }#foreach loop
    return $vulnhostobject
}#Get-VulnerableHost
            