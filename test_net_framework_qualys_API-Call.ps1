Measure-Command {
    
    $url = "https://qualysapi.qualys.com/msp/asset_search.php?target_ips=128.206.14.92&vuln_qid=105489"

    # Authentication
    $webclient = New-Object System.Net.WebClient
    $creds = New-Object System.Net.NetworkCredential("unver_dv4","Vr4e2l9yehgutUP0wOU!");
    $webclient.Credentials = $creds

  
    # GET
    $webClient.DownloadString($url) | ConvertFrom-Json

   

}