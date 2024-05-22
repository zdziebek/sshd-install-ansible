# URL to OpenSSHUtils zip file
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win32.zip"
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
