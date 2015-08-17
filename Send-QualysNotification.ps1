function Send-QualysNotification (){
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, valueFromPipeline=$true)][object[]] $inputobject
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

    $Outlook = New-Object -ComObject Outlook.Application
    $Mail = $Outlook.CreateItem(0)
    $Mail.To = 'spam@access.ironport.com'
    $mail.Attachments.Add($messagetoattach)
    $Mail.Sentonbehalfofname = "abuse@missouri.edu"
    $Mail.Subject = "Phishing E-Mail"
    $Mail.Body ="The following email is a phishing email: $originallink"
    $Mail.Send()


<#
Our inputobject variable needs the following properties
inputobject.owner
inputobject.assetgroup
inputobject.businessunit
vulntitle
vulnlevel
cve
QID
vendorref
vulnimpact
vulnsolution
exploitability
compliance
malware



it also needs all ips for this owner
ipaddress
dns
hostname
firstdetection
lastdetection
timesdetected

#>

$html = @" 
<!DOCTYPE html>
<html>
<head>
<title>Qualys Email Notification</title>
</head>
<body>

<p>Hello <b>$($inputobject.Owner)</b>,</p>
<br>

<p><b>As a Unit Manager of Asset Group(s): </b></p>
<ul>
    $(for ($a=0;$a -le $($inputobject.assetgroup).count; $a++){
        $assetgrouplist += "<li>$($inputobject.assetgroup[$a])</li>"
    })
	$($assetgrouplist)
</ul>

<p><b>With Business Unit(s): </b></p>
<ul>
	$(for ($a=0;$a -le $($inputobject.businessunit).count; $a++){
        $businessunitlist += "<li>$($inputobject.businessunit[$a])</li>"
    })
	$($businessunitlist)
</ul>

<p><b>The following vulnerability has been detected: </b></p>
<style>
table, td {
    border: 1px solid black;
}
</style>

<div>
	<table>
		<tr>
			<td align="center"><b>Vulnerability</b>: $($inputobject.vulntitle)<br>Level $($inputobject.vulnlevel) <img src="level4.jpg" alt="Level 4"></td>
			<td align="center"><b>Common Vulnerabilities and Exposures ID(s)</b>: 
            $(for ($a=0;$a -le $($inputobject.cve).count; $a++){
                $cvelist += "'\('$($inputobject.cve[$a])'\)'"
            })
	        $($cvelist)
            </td>
		</tr>
		<tr>
			<td align="center"><b>Qualys ID</b>: $($inputobject.QID)</td>
			<td align="center"><b>Vendor Reference</b>: $($inputobject.vendorref)</td>
		</tr>
	</table>
</div>
<br>
<p><b>The following IP(s) are vulnerable: </b></p>
<div>
	<table>
		<tr>
"@ | Out-File $outfilepath




        $(for ($a=0;$a -le $($inputobject.ipaddress).count; $a++){
			$vulnerablesystems = "<td><center><b>IP Address</b>: $($inputobject.ipaddress[$a])</td>
			                      <td><center><b>DNS Name</b>: $($inputobject.dns[$a])</td>
			                      <td><center><b>HOST Name</b>: $($inputobject.hostname[$a])</td>
			                      <td><center><b>First Detection</b>: $($inputobject.firstdetection[$a])</td>
			                      <td><center><b>Last Detection</b>: $($inputobject.lastdetection[$a])</td>
			                      <td><center><b>Times Detected</b>: $($inputobject.timesdetected[$a])</td>"
            $vulnerablesystems | Out-File $outfilepath
        })

$middle = @"
		</tr>
	</table>
</div>



<div align="center">
	<p><b><mark>UNPATCHED LEVEL 4/5 VULNERABILITIES WILL RESULT IN DEVICE DISCONNECTION FROM THE NETWORK AFTER 14 DAYS</mark></b></p>
</div>

<p><b>Possible Impact of Vulnerability:</b></p>
<ul>
	<li>$($inputobject.vulnimpact[$a])</li>
</ul>

<p><b>Possible Solution(s):</b></p>
<ul>
	<li>$($inputobject.vulnsolution[$a])</li>
	<li>Patch: <a href="http://lists.centos.org/pipermail/centos-announce/2015-April/021083.html">http://lists.centos.org/pipermail/centos-announce/2015-April/021083.html</a></li>
</ul>

<p><b>Compliance:</b></p>
<ul>
	<li>N/A</li>
</ul>

<p><b>Exploitability</b></p>
<ul>
	<li>There is no exploitability information for this vulnerability.</li>
</ul>

<p><b>Associated Malware</b></p>
<ul>
	<li>There is no malware information for this vulnerability.</li>
</ul>

<br>
<br>
<br>

<p align="center"><b><u><i>If you need assistance in vulnerability remediation, please contact ISAM at (573) 884-9112 or send an email to <a href="accounts@missouri.edu">accounts@missouri.edu</a></b></u></i></p>


</body>
</html>
"@


  

}
            