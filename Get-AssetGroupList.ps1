function Get-AssetGroupList ()
{      
    [cmdletbinding()]
    param (
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
      
    [xml]$assetgroupinfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php" -Credential $credential
    $titleObjs = @()
    foreach ($item in $assetgroupinfo.SelectNodes("/ASSET_GROUP_LIST/ASSET_GROUP")){    
        $titleProps = @{id=$($item.ID);
                        assetgroup=$($item.TITLE.InnerText);
                        ipaddress=$($item.SCANIPS.IP);
                        user=@{
                            firstname=$($item.ASSIGNED_USERS.ASSIGNED_USER.FIRSTNAME.InnerText);
                            lastname=$($item.ASSIGNED_USERS.ASSIGNED_USER.LASTNAME.InnerText);
                            login=$($item.ASSIGNED_USERS.ASSIGNED_USER.LOGIN.InnerText);
                            role=$($item.ASSIGNED_USERS.ASSIGNED_USER.ROLE.InnerText);
                            }
                        }

        $titleObj = New-Object PSObject -Property $titleProps
       
        $titleObjs += $titleObj   
    }#foreach loop
    return $titleObjs
}#Get-AssetGroupList
            