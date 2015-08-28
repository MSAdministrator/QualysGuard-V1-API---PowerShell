function Get-KnowledgebaseInfo ()
{
    [cmdletbinding()]
    param (     
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

    
   

    #this loop will iterate through all the hosturl arrays

    [xml]$vulninfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/knowledgebase_download.php?vuln_id=$($QID)" -Credential $credential
      
    foreach ($item in $vulninfo.SelectNodes("/VULNS/VULN")){
        $tempvulninfoobject = @()
            
        $objectproperties = @{QID=$($item.QID);
                            VULN_TYPE=$($item.VULN_TYPE.InnerText);
                            SEVERITY_LEVEL=$($item.SEVERITY_LEVEL);
                            TITLE=$($item.TITLE.InnerText);
                            PATCHABLE=$($item.PATCHABLE);
                            VENDOR_REFERENCE=$($item.VENDOR_REFERENCE_LIST.VENDOR_REFERENCE.InnerText);
                            CVE=$($item.CVE_ID_LIST);  
                            IMPACT=$($item.CONSEQUENCE.InnerText);
                            SOLUTION=$($item.SOLUTION.InnerText);
                            COMPLIANCE_TYPE=$($item.COMPLIANCE.COMPLIANCE_INFO.COMPLIANCE_TYPE.InnerText);
                            COMPLIANCE_DESCRIPTION=$($item.COMPLIANCE.COMPLIANCE_INFO.COMPLIANCE_DESCRIPTION.InnerText)
                                }

        $tempvulninfoobject = New-Object PSObject -Property $objectproperties
        
        $vulninfoobject += $tempvulninfoobject


    }#foreach loop

    return $vulninfoobject
}#Get-VulnerableHost
            