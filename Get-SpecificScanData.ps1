function get-specificscandata ()
{
    param (
        [parameter(Mandatory=$true,Position=1,HelpMessage="Please enter a scan reference ID")]
        [string]$scanreference,
        [System.Management.Automation.CredentialAttribute()]$credential,
        [switch]$services,
        [switch]$vulnerabilities
          ) 
    <#
    .SYNOPSIS 
    Query's QualysGuard SCAN API for a specific Scan details

    .DESCRIPTION
    Query's the API to find details about a specific scan time and IPs scanned
    Takes a string that is referencing a specific scan REFERENCE ID

    .PARAMETER ScanReference
    Specifices the specific scan ran by QualysGuard

    .PARAMETER Credential
    Specifices a set of credentials used to query the QualysGuard API

    .INPUTS
    None. You cannot pipe objects to Add-Extension.

    .OUTPUTS
   

    .EXAMPLE
    C:\PS> get-specificscandata "scan/1429034535.97692"
    File.txt

    #>
          

    [xml]$scanreportdetails = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/scan_report.php?ref=$scanreference" -Credential $credential

    if ($services -eq $true){

        #$IPsInScan = $scanreportdetails.scan.IP.value
        #$IPsInScan
        #$HostNameInScan = $scanreportdetails.scan.IP.name
        #$HostNameInScan
        #$OSInScan = $scanreportdetails.scan.IP.OS
        #$OSInScan
        $ServicesInScan = $scanreportdetails.scan.IP.services.cat.service.title
        $ServicesInScan
        #$VulnsInScan = $scanreportdetails.scan.IP.vulns.cat
        #$VulnsInScan
        #$AssetGroupsInScan = $scanreportdetails.scan.header.ASSET_GROUPS.ASSET_GROUP.ASSET_GROUP_TITLE
        #$AssetGroupsInScan
        #$vulnerabilitydetails = $scanreportdetails.scan.header
        #$vulnerabilitydetails #| Select-Object -Property * -ExcludeProperty InnerXML,OuterXML,InnerText #number,severity,title,name
        
        }
    if ($vulnerabilities -eq $true){$scanreportdetails.SCAN.IP.vulns.cat.vuln}

    #$scanreportdetails.SCAN.IP.services.cat | Select-Object -Property * -ExcludeProperty InnerXML,OuterXML,InnerText
    Write-Host $scanreportdetails.SCAN.IP.value -ForegroundColor Cyan

  #  foreach ($scannedhost in $scanreportdetails){
        

   # }



}




