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
function Get-QualysAssetGroupInformation
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
        $assetGroupInfo = @()
        [xml]$assetGroupInfo = Invoke-RestMethod -Uri "https://qualysapi.qualys.com/msp/asset_group_list.php" -Credential $credential
    }
    Process
    {
        foreach ($item in $assetGroupInfo.SelectNodes("/ASSET_GROUP_LIST/ASSET_GROUP")){
            for ($u=0; $u -lt $($item.ASSIGNED_USERS.ASSIGNED_USER.LOGIN).count;$u++){
                    if ($item.ASSIGNED_USERS.ASSIGNED_USER[$u].ROLE.InnerText -eq "Unit Manager"){

                                

                                $tempAssetGroupInfo = @()
                            
                                $props = @{userlogin=$($item.ASSIGNED_USERS.ASSIGNED_USER[$u].LOGIN.InnerText)
                                           userrole=$($item.ASSIGNED_USERS.ASSIGNED_USER[$u].ROLE.InnerText)
                                           assetgrouptitle=$($item.TITLE.InnerText)
                                           ip=$($item.SCANIPS.IP)
                                          }

                                $tempAssetGroupInfo = New-Object PSObject -Property $props
        
                                $results += $tempAssetGroupInfo
                                
                            }
                    
                }
        }
    }
                  
    End
    {
        Export-Clixml -Path C:\users\rickardj\Desktop\QualysData\assetgroupinfo.xml -InputObject $results
        return $results
    }
}