function Handle-Error {
    param (
        [string]$Message
    )
    Write-Error $Message
    exit 1
}

# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
if ($?) {
    Write-Output "OpenSSH Server installed successfully."
} else {
    Handle-Error "Failed to install OpenSSH Server."
}

# Start and set OpenSSH Server to start automatically
Start-Service sshd -ErrorAction Stop
if ($?) {
    Write-Output "OpenSSH Server started successfully."
} else {
    Handle-Error "Failed to start OpenSSH Server."
}

Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
if ($?) {
    Write-Output "OpenSSH Server set to start automatically."
} else {
    Handle-Error "Failed to set OpenSSH Server to start automatically."
}

# Add group 'ssh'
New-LocalGroup -Name ssh -ErrorAction Stop
if ($?) {
    Write-Output "Group 'ssh' created successfully."
} else {
    Handle-Error "Failed to create group 'ssh'."
}

# Add user 'ansible'
$UserPassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force -ErrorAction Stop
if ($?) {
    Write-Output "Password converted to secure string successfully."
} else {
    Handle-Error "Failed to convert password to secure string."
}

New-LocalUser -Name "ansible" -Password $UserPassword -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
if ($?) {
    Write-Output "User 'ansible' created successfully."
} else {
    Handle-Error "Failed to create user 'ansible'."
}

Add-LocalGroupMember -Group "ssh" -Member "ansible" -ErrorAction Stop
if ($?) {
    Write-Output "User 'ansible' added to group 'ssh' successfully."
} else {
    Handle-Error "Failed to add user 'ansible' to group 'ssh'."
}

# Add 'ssh' group to local administrators
Add-LocalGroupMember -Group "Administrators" -Member "ssh" -ErrorAction Stop
if ($?) {
    Write-Output "Group 'ssh' added to local administrators successfully."
} else {
    Handle-Error "Failed to add group 'ssh' to local administrators."
}

# Update OpenSSH configuration
$configPath = "C:\ProgramData\ssh\sshd_config"
# Ensure configuration allows groups and key-based authentication
try {
    Add-Content $configPath "`nAllowGroups ssh"
    Add-Content $configPath "`nPubkeyAuthentication yes"
    Add-Content $configPath "`nPasswordAuthentication no"
    Write-Output "OpenSSH configuration updated successfully."
} catch {
    Handle-Error "Failed to update OpenSSH configuration."
}

# Restart SSH service to apply configuration changes
Restart-Service sshd -ErrorAction Stop
if ($?) {
    Write-Output "OpenSSH service restarted successfully."
} else {
    Handle-Error "Failed to restart OpenSSH service."
}

# Generate SSH key for 'ansible'
$sshFolderPath = "C:\Users\ansible\.ssh"
try {
    New-Item -ItemType Directory -Force -Path $sshFolderPath
    ssh-keygen -t rsa -b 2048 -f "$sshFolderPath\id_rsa" -N ""
    Write-Output "SSH key generated successfully for 'ansible'."
} catch {
    Handle-Error "Failed to generate SSH key for 'ansible'."
}

# Add the provided SSH public key to 'authorized_keys'
$publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCe8U1Nu5wkiQ1i5SyCr3Fdb9Bzfyh9/Agg4sKfO9zqlspH6bmw1Y3RmiQf+aL7iv+Nj7P2ScSouRwgwO08W5YPryLSrWjTFuILHO9b1rMwraVgshYzkj3PHS4ChzA3wXAWra0aSnnjPfEBdxLmF8JazPMMQ0Dsnw7Qzytk426mnizOFNgbjYmJpox8UTEbI1Qt9YbBuEGKHWQW+2yYzZ9j9zxGSMnC0h5y7prJqyOmksZwrODxLx0yMcOYOv+dQkLNKW+igvSiFiD4UDFWvIb5llE4TSGLzS4f9NYYlLRXBdibWdUBmnojqR+MbTnlIqfaIJer8YeaCskjTSFAI3tVgFtEjQuQ3Qq0rcV/1PA1FW845JHtqPSuDSMAXTkmBLlklNk3dpPaUBr6CRdYbepSsN/+/+BNKZvRZkVC6ycJ+LdSfutXF130TYFYavc/L2DG6itJCmwlOHZDqd3/HxgLJ7ZBFLvPFdisyWHuP69sJgtpvihBvPyvFXMPcUTjU00= mzdziebko@DESKTOP-3HHGGK7"
$authorizedKeysPath = "$sshFolderPath\authorized_keys"
try {
    Add-Content $authorizedKeysPath $publicKey
    Write-Output "SSH public key added to 'authorized_keys' successfully."
} catch {
    Handle-Error "Failed to add SSH public key to 'authorized_keys'."
}

# Set the correct permissions for the .ssh folder and authorized_keys file
try {
    icacls $sshFolderPath /grant ansible:`(F`)
    icacls $authorizedKeysPath /inheritance:r /grant ansible:`(F`)
    icacls $authorizedKeysPath /inheritance:r /grant "NT AUTHORITY\SYSTEM:`(F`)"
    Write-Output "Permissions set for .ssh folder and authorized_keys file successfully."
} catch {
    Handle-Error "Failed to set permissions for .ssh folder and authorized_keys file."
}

# Open SSH port 22 in the firewall

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}
if ($?) {
    Write-Output "Firewall rule created successfully to open port 22."
} else {
    Handle-Error "Failed to create firewall rule to open port 22."
}

# Set the default shell for OpenSSH to PowerShell
try {
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    Write-Output "Default shell for OpenSSH set to PowerShell successfully."
} catch {
    Handle-Error "Failed to set default shell for OpenSSH to PowerShell."
}

# Restart SSH service to apply any changes
Restart-Service sshd -ErrorAction Stop
if ($?) {
    Write-Output "OpenSSH service restarted successfully."
} else {
    Handle-Error "Failed to restart OpenSSH service."
}

Write-Output "Setup complete."
