<# Set and encrypt credentials to file using default method #>

 #enter username and password when prompted
$credential = Get-Credential

#coverts your password to a securestring that can be used multiple times
$credential.Password | ConvertFrom-SecureString | Set-Content c:\ftp\encrypted_password.txt

