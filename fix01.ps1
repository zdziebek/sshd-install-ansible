# URL to OpenSSHUtils zip file (replace with actual URL if available)
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.1p1/OpenSSHUtils.zip"
$zipPath = "$env:TEMP\OpenSSHUtils.zip"
$extractPath = "$env:ProgramFiles\OpenSSHUtils"

# Download the OpenSSHUtils zip file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

# Extract the zip file
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Import the OpenSSHUtils module
Import-Module "$extractPath\OpenSSHUtils.psd1" -Force

# Fix permissions on sshd_config
Repair-SshdConfigPermission -FilePath C:\ProgramData\ssh\sshd_config

# Fix permissions on a specified host key
Repair-SshdHostKeyPermission -FilePath C:\ProgramData\ssh\ssh_host_ecdsa_key

# Fix permissions on a specified authorized_key
Repair-AuthorizedKeyPermission -FilePath C:\Users\ansible\.ssh\authorized_keys

# Fix permissions on a specific ssh_config
Repair-UserSshConfigPermission -FilePath C:\Users\ansible\.ssh\config

# Fix permissions on a user key
Repair-UserKeyPermission -FilePath C:\Users\ansible\.ssh\id_rsa

Write-Output "Permissions repair complete."
