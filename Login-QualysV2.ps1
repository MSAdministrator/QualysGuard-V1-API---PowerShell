[String]$CookieJar = "$ScriptName.cookies"
Set-Location -Path "Z:\_Box\_GitHub\QualysGuard-V1-API---PowerShell"

<#
       $CookieJar - this is where we will store the cookie that Qualys will issue so you don't need to relogin everytime.
       The Set-Location function is part of Powershell and should be set to where your running this script; shortcut later.
       Your path to CURL will be relative to this.
#>


function LoginQualys(){
<#
.SYNOPSIS
Login to the Qualys Platform
.DESCRIPTION
Login to the Qualys Platform.
A custom User Agent string could be used for other things and monitoring so I use custom ones for my tools. hint; so do malware authors.
The Get-QualysAPIAccountCred will call a function to return an Object with the credentials to login into Qualys.
We then create the Session String
And finally Invoke the full command. The results of the command go to the Result Object "xml" which you can parse later for other details.
.PARAMETER NONE
.EXAMPLE
LoginQualys
#>
       [PSObject]$myCred = Get-QualysAPIAccountCred
       [String]$SUrl= 'https://qualysapi.qualys.com:443/api/2.0/fo/session/'
       [String]$UA = """X-Requested-With: Powershell"""
       [String]$CURL = ".\curl.exe"
       [String]$SessionLogin = " $CURL --header $UA --dump-header `""+$CookieJar+"`" --insecure --data `"action=login&username="+$myCred.username+"&password="+$myCred.password+"`" `""+$SUrl+"`" "
       [System.Object]$Result = Invoke-Expression $SessionLogin
}

 

 

 
function Get-QualysAPIAccountCred {
<#
.SYNOPSIS
Returns a PSObject of Credentials
.DESCRIPTION
Creates a PSObject and puts the Qualys Credentails in it.
.PARAMETER NONE
.NOTES
       Should encrypt later.
.EXAMPLE
[PSObject]$Cred = Get-QualysAPIAccountCred
#>

        #### MY EDITS ####
        if ($CookieJar){
            $cred = Get-Credential
            }
        
        
        
        #### MY EDITS ####

       $CredentialObj  = New-Object -Type PSObject
       $CredentialObj | Add-Member -MemberType NoteProperty -Name username -Value 'unver_dv4' -Force
       $CredentialObj | Add-Member -MemberType NoteProperty -Name password -Value $cred.GetNetworkCredential().Password -Force
       return [PSObject]$CredentialObj
}

 
function LogoutQualys(){
<#
.SYNOPSIS
Logout of the Qualys Platform
.DESCRIPTION
Logout of the Qualys Platform
.PARAMETER NONE
.EXAMPLE
LogoutQualys
#>
       [String]$CURL = ".\curl.exe"
       [String]$UA = """X-Requested-With: Powershell"""
       [String]$SUrl= 'https://qualysapi.qualys.com:443/api/2.0/fo/session/'
       [String]$SessionLogout = " $CURL --header $UA --cookie `""+$CookieJar+"`" --insecure --data `"action=logout`" `""+$SUrl+" `""
       [System.Object]$Result = Invoke-Expression $SessionLogout
}
 
function Clean-up {
<#
       Here we just clean up the Cookiejar by testing to see if it is present then remove it.
#>
       if(Test-Path $CookieJar){Remove-Item -Force $CookieJar}
}
 
function Main {
       LoginQualys
       LogoutQualys
       Clean-up
}
 
. Main