function Update-Status {
    param (
        [int]$Step,
        [string]$Message
    )
    Write-Host "[$Step/17] $Message"
}

$step = 1

# Install OpenSSH Server
Update-Status $step "Installing OpenSSH Server..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
$step++

# Start and set OpenSSH Server to start automatically
Update-Status $step "Starting OpenSSH Server..."
Start-Service sshd
$step++

Update-Status $step "Setting OpenSSH Server to start automatically..."
Set-Service -Name sshd -StartupType 'Automatic'
$step++

# Add group 'ssh'
Update-Status $step "Creating group 'ssh'..."
New-LocalGroup -Name ssh
$step++

# Add user 'ansible'
Update-Status $step "Converting password to secure string..."
$UserPassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$step++

Update-Status $step "Creating user 'ansible'..."
New-LocalUser -Name "ansible" -Password $UserPassword -PasswordNeverExpires -UserMayNotChangePassword
$step++

Update-Status $step "Adding user 'ansible' to group 'ssh'..."
Add-LocalGroupMember -Group "ssh" -Member "ansible"
$step++

# Add 'ssh' group to local administrators
Update-Status $step "Adding group 'ssh' to local administrators..."
Add-LocalGroupMember -Group "Administrators" -Member "ssh"
$step++

# Update OpenSSH configuration
Update-Status $step "Updating OpenSSH configuration..."
$configPath = "C:\ProgramData\ssh\sshd_config"
Add-Content $configPath "`nAllowGroups ssh"
Add-Content $configPath "`nPubkeyAuthentication yes"
Add-Content $configPath "`nPasswordAuthentication no"
$step++

# Enable debug logging in sshd_config
Update-Status $step "Enabling debug logging in sshd_config..."
Add-Content $configPath "`nLogLevel DEBUG3"
$step++

# Restart SSH service to apply configuration changes
Update-Status $step "Restarting OpenSSH service..."
Restart-Service sshd
$step++

# Generate SSH key for 'ansible'
Update-Status $step "Generating SSH key for 'ansible'..."
$sshFolderPath = "C:\Users\ansible\.ssh"
New-Item -ItemType Directory -Force -Path $sshFolderPath
ssh-keygen -t rsa -b 2048 -f "$sshFolderPath\id_rsa" -N ""
$step++

# Add the provided SSH public key to 'authorized_keys'
Update-Status $step "Adding SSH public key to 'authorized_keys'..."
$publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCe8U1Nu5wkiQ1i5SyCr3Fdb9Bzfyh9/Agg4sKfO9zqlspH6bmw1Y3RmiQf+aL7iv+Nj7P2ScSouRwgwO08W5YPryLSrWjTFuILHO9b1rMwraVgshYzkj3PHS4ChzA3wXAWra0aSnnjPfEBdxLmF8JazPMMQ0Dsnw7Qzytk426mnizOFNgbjYmJpox8UTEbI1Qt9YbBuEGKHWQW+2yYzZ9j9zxGSMnC0h5y7prJqyOmksZwrODxLx0yMcOYOv+dQkLNKW+igvSiFiD4UDFWvIb5llE4TSGLzS4f9NYYlLRXBdibWdUBmnojqR+MbTnlIqfaIJer8YeaCskjTSFAI3tVgFtEjQuQ3Qq0rcV/1PA1FW845JHtqPSuDSMAXTkmBLlklNk3dpPaUBr6CRdYbepSsN/+/+BNKZvRZkVC6ycJ+LdSfutXF130TYFYavc/L2DG6itJCmwlOHZDqd3/HxgLJ7ZBFLvPFdisyWHuP69sJgtpvihBvPyvFXMPcUTjU00= mzdziebko@DESKTOP-3HHGGK7"
$authorizedKeysPath = "$sshFolderPath\authorized_keys"
Add-Content $authorizedKeysPath $publicKey
$step++

# Open SSH port 22 in the firewall
Update-Status $step "Creating firewall rule to open port 22..."
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (TCP-In)" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
$step++

# Set the default shell for OpenSSH to PowerShell
Update-Status $step "Setting default shell for OpenSSH to PowerShell..."
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
$step++

# Restart SSH service to apply any changes
Update-Status $step "Restarting OpenSSH service..."
Restart-Service sshd
$step++

Write-Output "Setup complete."
