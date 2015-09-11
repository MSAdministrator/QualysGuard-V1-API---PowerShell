<#
.Synopsis
   This function gets Business Unit information
.DESCRIPTION
   This function is primarily called from the Get-NofiticationData function to gather busines unit information.
   Once we have this information it used to begin processing notification emails
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Get-QualysBusinessUnitInformation
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Please provide a crednetial obejct")]
                   [ValidateNotNullOrEmpty()]
                   [System.Management.Automation.CredentialAttribute()]$credential
        ) 

    Begin
    {
        $results = @()
        $businessUnitInfo = @()
        [xml]$businessUnitInfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/user_list.php" -Credential $credential
    }
    Process
    {
        foreach ($item in $businessUnitInfo.SelectNodes("/USER_LIST_OUTPUT/USER_LIST/USER")){
            if ($item.UNIT_MANAGER_POC -eq "1"){
                if ($item.BUSINESS_UNIT.InnerText -ne "MU DoIT CSG"){
                    if ($item.BUSINESS_UNIT.InnerText -ne "MU DoIT CSG Linux"){
                        if ($item.BUSINESS_UNIT.InnerText -ne "MU DoIT CSG Windows"){
                            
                            $tempBusinessUnitInfo = @()
                            
                            $props = @{userlogin=$($item.USER_LOGIN)
                                       firstname=$($item.CONTACT_INFO.FIRSTNAME.InnerText)
                                       lastname=$($item.CONTACT_INFO.LASTNAME.InnerText)
                                       title=$($item.CONTACT_INFO.TITLE.InnerText)
                                       email=$($item.CONTACT_INFO.EMAIL.InnerText)
                                       userrole=$($item.USER_ROLE)
                                       businessunit=$($item.BUSINESS_UNIT.InnerText)
                            }

                            $tempBusinessUnitInfo = New-Object PSObject -Property $props
        
                            $results += $tempBusinessUnitInfo

                        }

                    }

                }
                  

            }
        }
    }
    End
    {
        Export-Clixml -Path C:\users\rickardj\Desktop\QualysData\businessunitinfo.xml -InputObject $results
        return $results
    }
}