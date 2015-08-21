function Save-HostInformationToDatabase {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, valueFromPipeline=$true)][object[]] $inputobject
        )
    BEGIN {
        #write-host "inputobject count: "$inputobject.Count
        $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = "Server=UMHC-SECSCAN04;Database=QualysGuardAPI;Trusted_Connection=True;"
        $connection.open()
    }
    PROCESS {
        write-host "inputobject count: "$inputobject.Count
        $command = New-Object -TypeName System.Data.SqlClient.SqlCommand
        $command.Connection = $connection

        $sql = "DELETE FROM Server_Table WHERE ipaddress = '$($inputobject.ipaddress)' AND DNS_Name = '$($inputobject.dnsname)'"
        Write-Debug "Executing $sql"
        $command.CommandText = $sql
        $command.ExecuteNonQuery() | Out-Null

        $sql = "INSERT INTO Server_Table (ipaddress, OS_Type, DNS_Name, QID, Last_Scan_Date) VALUES 
                ('$($inputobject.ipaddress)','$($inputobject.ostype)','$($inputobject.dnsname)','$($inputobject.QID)','$($inputobject.lastscandate)')"
        Write-Debug "Executing $sql"
        $command.CommandText = $sql
        $command.ExecuteNonQuery() | Out-Null
    }

    END {
        $connection.Close()
    }
        
}


function Get-HostNameforQualysAPI {

    $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = "Server=UMHC-SECSCAN04;Database=QualysGuardAPI;Trusted_Connection=True;"
    $connection.open()

    $command = New-Object -TypeName System.Data.SqlClient.SqlCommand
    $command.Connection = $connection

    $sql = "SELECT ipaddress FROM Server_Table"
    Write-Debug "Executing $sql"
    $command.CommandText = $sql

    $reader = $command.ExecuteReader()

    while ($reader.read()){
        $ipaddress = $reader.GetSqlString(0)
        Write-Output $ipaddress
        }
    $connection.Close()

}