#You have a list of your vulnerable hosts which contains custom properties
#Create a seperate group of objects foreach QID
#Foreach object we will need to sort by primary contact

#(BUILD SEPERATE FUNCTION)Find primary contact for each IP/Host


#for QID object.count 
    #foreach Primary Contact
        #foreach IP in QID
        #if equal 
            #add to temporary object
            #after searching all IPs for primary contact[$i]
                #$returnvalue = send to check notification status function
                    #Call email function and pass that ($returnvalue) object to it
                  
    

function Check-EmailNotificationStatus{

#foreach value

foreach ($item in $inputobject){
 

 #look through exception databse for match of 
        #QID
        #IP
        #PContact
    $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = "Server=UMHC-SECSCAN04;Database=QualysGuardAPI;Trusted_Connection=True;"
    $connection.open()

    $command = New-Object -TypeName System.Data.SqlClient.SqlCommand
    $command.Connection = $connection

    $sql = "SELECT QID,ipaddress,PContact FROM Server_Table where QID='$($inputobject.QID)' AND ipaddress='$($inputobject.ipaddress)' AND PContact='$($inputobject.pcontact)'"
    Write-Debug "Executing $sql"
    $command.CommandText = $sql

    

    $reader = $command.ExecuteReader()

    while ($reader.read()){
        $match = $reader.GetSqlString(0)
        
        if ($match -eq $true){
            if ($reader.status -ne "Granted"){
        
        }
    $connection.Close()
   
            
    
        #if Match
            #If status equals NOT granted{
                #look at last_notification_date
                    #if last_noficiation_date is less than $scan_date & 5 day buffer 
                        #Example: if last_notification_date=June 1st.  Last scan date has to be greater than or equal to June 6th.
                        #update database - Last_notification_date = todays date & number of notifications sent is incremented
                        #Add to return object for email
                    #else
                        #do not send notification
            #if Status equals granted 
                #do nothing        
        #if NOT match
            #add it to the return object for email
    }
   
#return object for email notification



}