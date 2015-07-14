function Send-QualysNotification ()
{
    param (
        [parameter(ParameterSetName="set1",
                   HelpMessage="Please enter a single IP or a range of IPs")]
                   [ValidateNotNullOrEmpty()]
                   [ValidatePattern('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')]
                   [string]$targetip,

        [parameter(ParameterSetName="set2",
                   HelpMessage="Please enter an Asset Group or comma seperated list of Asset Groups. Default is All")]
                   [ValidateNotNullOrEmpty()] 
                   [string]$targetag,
        
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
    Send email notifications to asset owners about vulnerabilities

    .DESCRIPTION
    Query's the API to find details about a specific Asset Group(s)
    Takes input as the Asset Group title (string)

    .PARAMETER ScanReference
    Specifices the Asset Group you are wanting information about

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> Get-AssetGroupIPs -agtitle "MU AS DC Assets (DC)" -credential $cred
    

    #>
          

$emailbody = @"
<p>Hello $username,</p>
<p>As a Unit Manager of the Asset Group(s):</p>
<ul>
<li>$assetgroup</li>
<li>$assetgroup</li>
</ul>
<p>With Business Unit():</p>
<ul>
<li>$busunit</li>
<li>$busunit</li>
</ul>
<p>The following IP(s) has been identified as vulnerable:</p>
<p>IP Address: <u>$ipaddress</u><t><t>DNS Name: <u>$dnsname</u></p>
<div align="center">
<p>Host Name: <u>$hostname</u></p>
<p>Vulnerability: <u>$vulnname</u> | $vulnlevel $vulnimage </p>
<p>QID: <u>$qidnum</u></p>




"@

    $Outlook = New-Object -ComObject Outlook.Application
    $Mail = $Outlook.CreateItem(0)
    $Mail.To = 'spam@access.ironport.com'
    $mail.Attachments.Add($messagetoattach)
    $Mail.Sentonbehalfofname = "abuse@missouri.edu"
    $Mail.Subject = "Phishing E-Mail"
    $Mail.Body ="The following email is a phishing email: $originallink"
    $Mail.Send()




  

            }
            