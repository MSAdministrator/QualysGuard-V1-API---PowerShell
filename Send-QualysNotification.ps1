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

    $DoITLogoBase64 = '<img src="data:image/jpg;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\doit_logo.jpg -encoding byte))+'">'
    $level1 = '<img src="data:image/png;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level1.png -encoding byte))+'">'
    $level2 = '<img src="data:image/png;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level2.png -encoding byte))+'">'
    $level3 = '<img src="data:image/png;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level3.png -encoding byte))+'">'
    $level4 = '<img src="data:image/png;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level4.png -encoding byte))+'">'
    $level5 = '<img src="data:image/png;base64,'+[convert]::ToBase64String((get-content Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level5.png -encoding byte))+'">'

    $assetgrouplist = @()
    $businessunitlist = @()
    $cvelist = @()
    $vulnerablesystems = @()
    $imagepath = "Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images"
    $tempunitManagerLogin = @()
    $tempUnitManagerName = @()
    $unitManagerLogin = @()
    $unitManagerName = @()
    $assetgrouplist = @()
    $businessunitlist = @()
    $cvelist = @()
    $vulnerablesystems = @()
    $image = @()
    $alt = @()


    for ($a=0;$a -lt $($inputobject.businessunitinfo).count;$a++){
        $tempunitManagerLogin += $($inputobject.businessunitinfo[$a].userlogin)
        $tempUnitManagerName += "$($inputobject.businessunitinfo[$a].firstname) $($inputobject.businessunitinfo[$a].lastname)" 
    }
    $unitManagerLogin = $tempunitManagerLogin | sort -Unique
    $unitManagerName = $tempUnitManagerName | sort -Unique

for ($u=0;$u -lt $unitManagerLogin.count;$u++){ 
    foreach ($item in $inputobject){
       
        if ($item.businessunitinfo.userlogin -eq $unitManagerLogin[$u]){
              
            
                $assetgrouplist += "<li>$($item.businessunitinfo.assetgroupinfo.assetgrouptitle)</li>"
            

            
                $businessunitlist += "<li>$($item.businessunitinfo.businessunit)</li>"
            

            
			    $vulnerablesystems += "<tr><td>$($item.businessunitinfo.assetgroupinfo.vulnerablehost.vulnhost.ipaddress)</td>
			                           <td>$($item.businessunitinfo.assetgroupinfo.vulnerablehost.vulnhost.dnsname)</td>
			                           <td>$($item.businessunitinfo.assetgroupinfo.vulnerablehost.vulnhost.netbios)</td>
			                           <td>$($item.businessunitinfo.assetgroupinfo.vulnerablehost.vulnhost.lastscandate)</td></tr>"
            }
        }
        
$html = @" 
<!DOCTYPE html>
<html>
<head>
<title>Qualys Email Notification</title>



<style type="text/css">
    @media only screen and (max-width: 480px){
        .emailButton{
            max-width:600px !important;
            width:100% !important;
        }

        .emailButton a{
            display:block !important;
            font-size:18px !important;
        }
    }

</style>




</head>
<body style="color: #000000; font-family: Arial, sans-serif; font-size: 12px; line-height: 20px;">

<table border="0" cellpadding="0" cellspacing="0" width="100%">
<div id="header" >
        <div style="float:left; margin-top:20px" >
            <img src="https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/doit_logo.jpg" height="70" alt="logo" align="left" />
        </div>
        <div style="float:right; margin-top:20px" >
            <img src="https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/mu_logo.png" height="70" alt="logo" align="right" />
        </div>
    </div>
</table>
<table border="0" cellpadding="0" cellspacing="0" class="emailButton" style="-webkit-border-radius: 3px; -moz-border-radius: 3px; border-radius: 5px; background-color:#505050; border:1px solid #353535;" width="100%" arcsize="13%">
    <tr>
        <td align="center" valign="middle" style="color:#FFFFFF; font-family:Helvetica, Arial, sans-serif; font-size:16px; font-weight:bold; letter-spacing:-.5px; line-height:150%; padding-top:15px; padding-right:30px; padding-bottom:15px; padding-left:30px;">
            <a style="color:#FFFFFF; text-decoration:none;">ISAM Enterprise Vulnerability Scanning Notification</a>
        </td>
    </tr>
</table>
</div>
<p>Date: $(Get-Date) </p>

<div style="color:#00000; font-family:Helvetica, Arial, sans-serif; font-size:12px; letter-spacing:-.5px; line-height:150%; padding-top:5px; padding-right:5px; padding-bottom:5px; padding-left:5px;">

<p>Hello <b>$($unitManagerName[$u])</b>,</p>
<p><b>You have been identified as the Primary Contact for the following Business Unit(s): </b></p>
<ul>
	$($businessunitlist | sort -Unique)
</ul>
<p><b>The following Asset Group(s) belong to your Business Unit: </b></p>
<ul>
	$($assetgrouplist | sort -Unique)
</ul>
</div>
<table border="0" cellpadding="0" cellspacing="0" class="emailButton" style="-webkit-border-radius: 3px; -moz-border-radius: 3px; border-radius: 5px; background-color:#505050; border:1px solid #353535;" width="100%" arcsize="13%">
    <tr>
        <td align="center" valign="middle" style="color:#FFFFFF; font-family:Helvetica, Arial, sans-serif; font-size:16px; font-weight:bold; line-height:150%; padding-top:15px; padding-right:30px; padding-bottom:15px; padding-left:30px;">
            <a style="color:#FFFFFF; text-decoration:none;">The following vulnerability has been detected</a>
        </td>
    </tr>
</table>
	
            $(switch ($inputobject.QualysKBInfo[0].SEVERITY_LEVEL){
                1 { $image = "https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/level1.png"
                    $alt = "Level 1" 
                    }
                2 { $image = "https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/level2.png" 
                    $alt = "Level 2" 
                    }
                3 { $image = "https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/level3.png" 
                    $alt = "Level 3"
                    }
                4 { $image = "https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/level4.png" 
                    $alt = "Level 4"
                    }
                5 { $image = "https://raw.githubusercontent.com/MSAdministrator/QualysGuard-V1-API---PowerShell/master/images/level5.png" 
                    $alt = "Level 5"
                    }
                })

<style>
th,td {border: 1px solid black;}
</style>



	<table width ="100%" cellspacing="0" cellpadding="0" border="0" style="color:#00000; font-family:Helvetica, Arial, sans-serif; font-size:12px; line-height:150%; padding-top:5px; padding-right:5px; padding-bottom:5px; padding-left:5px;">          
            <tr>
                <th width="150" bgcolor="#A0A0A0"><b>Vulnerability</b>:</th>
			    <td>$($inputobject.QualysKBInfo[0].Title)</td>
            </tr>
            <tr>
                <th width="150" bgcolor="#A0A0A0""><b>DIAGNOSIS</b>:</th>
			    <td>$($inputobject.QualysKBInfo[0].DIAGNOSIS)</td>
            </tr>
            <tr>
                <th width="150" bgcolor="#A0A0A0"><b>IMPACT</b>:</th>
			    <td>$($inputobject.QualysKBInfo[0].CONSEQUENCE)</td>
            </tr>
            <tr>
                <th width="150" bgcolor="#A0A0A0"><b>Level</b>:</th>
                <td><img src="$($image)" alt="$($alt)" /></td>
            </tr>

            <tr>
                <th width="150" bgcolor="#A0A0A0"><b>Common Vulnerabilities and Exposures ID(s)</b>:</th>
			    <td>
           $(if (($inputobject.QualysKBInfo[0].CVE) -eq $null){
                $cvelist = "No CVE data at this time"
                $($cvelist)
            }
           else {
                $(foreach ($cve in $inputobject.QualysKBInfo[0].cve.cve_id){
	                $cvelist += "CVE: $($cve.id.InnerText) URL: $($cve.url.InnerText)"

                })
                $($cvelist -join "`n")
            })
            </td>
            </tr>
            <tr>
			    <th width="150" bgcolor="#A0A0A0"><b>Qualys ID</b>:</th>
                <td>$($inputobject.QualysKBInfo[0].QID)</td>
            </tr>
            <tr>
			    <th width="150" bgcolor="#A0A0A0"><b>Vendor Reference</b>:</th>
                <td>$(if ($inputobject.QualysKBInfo[0].VENDOR_REFERENCE -ne $null){$($inputobject.QualysKBInfo[0].VENDOR_REFERENCE)})</td>
		    </tr>
	</table>

<br>
<table border="0" cellpadding="0" cellspacing="0" class="emailButton" style="-webkit-border-radius: 3px; -moz-border-radius: 3px; border-radius: 5px; background-color:#505050; border:1px solid #353535;" width="100%" arcsize="13%">
    <tr>
        <td align="center" valign="middle" style="color:#FFFFFF; font-family:Helvetica, Arial, sans-serif; font-size:16px; font-weight:bold; line-height:150%; padding-top:15px; padding-right:30px; padding-bottom:15px; padding-left:30px;">
            <a style="color:#FFFFFF; text-decoration:none;">The following IP(s) are vulnerable:</a>
        </td>
    </tr>
</table>



	<table align="middle" style="color:#00000; font-family:Helvetica, Arial, sans-serif; font-size:12px; line-height:150%; padding-top:5px; padding-right:5px; padding-bottom:5px; padding-left:5px;">
		<tr>
            <th bgcolor="#A0A0A0"><center><b>IP Address</b>:</th>
            <th bgcolor="#A0A0A0"><center><b>DNS Name</b>:</th>
            <th bgcolor="#A0A0A0"><center><b>NETBIOS Name</b>:</th>
            <th bgcolor="#A0A0A0"><center><b>Last Scan Date</b>:</th>
        </tr>
        $($vulnerablesystems)
	</table>




<div align="center" style="color:#00000; font-family:Helvetica, Arial, sans-serif; font-size:18px; line-height:150%; padding-top:5px; padding-right:5px; padding-bottom:5px; padding-left:5px;">
	<p><b><mark>UNPATCHED LEVEL 4/5 VULNERABILITIES MAY RESULT IN DEVICE DISCONNECTION FROM THE NETWORK AFTER 14 DAYS</mark></b></p>
</div>


<br>
<table border="0" cellpadding="0" cellspacing="0" class="emailButton" style="-webkit-border-radius: 3px; -moz-border-radius: 3px; border-radius: 5px; background-color:#505050; border:1px solid #353535;" width="100%" arcsize="13%">
    <tr>
        <td align="center" valign="middle" style="color:#FFFFFF; font-family:Helvetica, Arial, sans-serif; font-size:16px; font-weight:bold; line-height:150%; padding-top:15px; padding-right:30px; padding-bottom:15px; padding-left:30px;">
            <a style="color:#FFFFFF; text-decoration:none;">Additional Information</a>
        </td>
    </tr>
</table>

<table width="100%" style="color:#00000; font-family:Helvetica, Arial, sans-serif; font-size:12px; line-height:150%; padding-top:5px; padding-right:5px; padding-bottom:5px; padding-left:5px;">
		<tr>
            <th bgcolor="#A0A0A0"><center><b>Possible Solutions</b>:</th>
            <th bgcolor="#A0A0A0"><center><b>Exploitability</b>:</th>
            <th bgcolor="#A0A0A0"><center><b>Knwon Malware</b>:</th>
        </tr>
        <tr>
            <td>$($inputobject.QualysKBInfo[0].SOLUTION)</td>
            <td>
                $(if (($inputobject.QualysKBInfo[0].EXPLOITABILITY) -eq $null){
                    $exploitdata = "No Exploitation data at this time"
                    $($exploitdata)
                }
                else {
                    $exploitdata += "$($inputobject.QualysKBInfo[0].EXPLOITABILITY)"
                    $($exploitdata)
                })
            </td>
            <td>
                $(if (($inputobject.QualysKBInfo[0].MALWARE) -eq $null){
                    $malwaredata = "No Malware data at this time"
                    $($malwaredata)
                }
                else {
                    $malwaredata += "$($inputobject.QualysKBInfo[0].MALWARE)"
                    $($malwaredata)
                })
            </td>
	</table>

<br>
<br>
<br>

<p align="center"><b><u><i>If you need assistance with vulnerability remediation, please contact ISAM at (573) 884-9112 or send an email to <a href="qualys@missouri.edu">qualys@missouri.edu</a></b></u></i></p>


</body>
</html>
"@

#write-host "HTML output: "$html

$Outlook = New-Object -ComObject Outlook.Application
  #  $logo = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\doit_logo.jpg")
  #  $logo.ContentId = "logo"
  #  $level1 = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level1.png")
  #  $level1.ContentId = "level1"
  #  $level2 = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level2.png")
  #  $level2.ContentId = "level2"
  #  $level3 = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level3.png")
  #  $level3.ContentId = "level3"
  #  $level4 = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level4.png")
  #  $level4.ContentId = "level4"
  #  $level5 = New-Object Net.Mail.Attachment("Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell\images\level5.png")
  #  $level5.ContentId = "level5"

    $Mail = $Outlook.CreateItem(0)
    $Mail.To = 'rickardj@missouri.edu'
    $Mail.Sentonbehalfofname = "abuse@missouri.edu"
    $Mail.Subject = "Notification: Vulnerability Identified"
    
    $Mail.HTMLBody =$html
    $Mail.Send()
   # $Mail.Dispose()

    $assetgrouplist = @()
    $businessunitlist = @()
    $vulnerablesystems = @()

    }#end of For loop


}
            