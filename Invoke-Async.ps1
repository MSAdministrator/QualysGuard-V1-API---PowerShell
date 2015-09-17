function Invoke-Async 
{
    [CmdletBinding()]
	Param
	(
        [Parameter(Position=0,Mandatory=$true)][System.Object[]]$ObjArray
		,[Parameter(Position=1,Mandatory=$true)][ScriptBlock]$ScriptBlock
		,[Parameter(Position=2, Mandatory=$true)][Alias("Threads")][int]$PoolSize
		,[Parameter(Position=3,Mandatory=$false)][int]$Timeout = 100000
	)

	$jobs = @{}
    $pipelines = @{}
    $WaitHandles = @{}
    
    # Create a runspace pool
	$pool = [RunspaceFactory]::CreateRunspacePool(1, $PoolSize)
	$pool.ThreadOptions = "ReuseThread"
	$pool.ApartmentState = "STA"
    $pool.Open()
    
    # Iterate each object.  Create a pipeline and pass each object to the script block in the pipeline    
	for($i = 1;$i -le $ObjArray.Length;$i++) 
	{
		$pipelines[$i] = [System.Management.Automation.PowerShell]::create()

	   	$pipelines[$i].RunspacePool = $pool 

	 	[void]$pipelines[$i].AddScript($ScriptBlock).AddArgument($ObjArray[$i])

	   	$jobs[$i] = $pipelines[$i].BeginInvoke();
	   	
	   	$WaitHandles[$i] = $jobs[$i].AsyncWaitHandle  	
	}

    # Grab the results of each job.
	for($i = 1;$i -le $ObjArray.Length;$i++) 
	{
		try 
		{  	
			if($WaitHandles[$i].WaitOne($Timeout))
			{
				$pipelines[$i].EndInvoke($jobs[$i])
			} else
			{
				"Job $i failed"
				$pipelines[$i].Stop()
			}
			    	
	    	Write-Progress -Activity "Running Jobs" -Status "Percent Complete" -PercentComplete $(($i/$ObjArray.Length) * 100)
		} catch 
		{  
			Write-Warning "error: $_" 
		}

		$pipelines[$i].Dispose();
	}	
	
    $pool.Close()
}

