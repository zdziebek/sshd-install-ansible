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

# Add user 'ansible' without a password
Update-Status $step "Creating user 'ansible'..."
New-LocalUser -Name "ansible" -Password (ConvertTo-SecureString "zaq1@WSX" -AsPlainText -Force) -PasswordNeverExpires -UserMayNotChangePassword
$step++

Update-Status $step "Adding user 'ansible' to group 'ssh'..."
Add-LocalGroupMember -Group "ssh" -Member "ansible"
$step++

# Add user 'ansible' to local administrators
Update-Status $step "Adding user 'ansible' to local administrators..."
Add-LocalGroupMember -Group "Administrators" -Member "ansible"
$step++

# Download and apply OpenSSH configuration
Update-Status $step "Downloading and applying OpenSSH configuration..."
$configUrl = "https://raw.githubusercontent.com/zdziebek/sshd-install-ansible/main/sshd.config"
$configPath = "C:\ProgramData\ssh\sshd_config"
Invoke-WebRequest -Uri $configUrl -OutFile $configPath
$step++

# Restart SSH service to apply configuration changes
Update-Status $step "Restarting OpenSSH service..."
Restart-Service sshd
$step++

# Ensure the .ssh directory exists
Update-Status $step "Ensuring .ssh directory exists..."
$sshFolderPath = "C:\Users\ansible\.ssh"
New-Item -ItemType Directory -Force -Path $sshFolderPath
$step++

# Add new SSH public keys to authorized_keys
Update-Status $step "Adding new SSH keys to authorized_keys..."
$authorizedKeysPath = "$sshFolderPath\authorized_keys"
if (-Not (Test-Path $authorizedKeysPath)) {
    New-Item -ItemType File -Path $authorizedKeysPath
}

$keys = @(
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPX18Jv6ASyiiX9x9K2shNSQSSDEKH814MK2CPJk3sEa WSL-Alpine",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDp4Y5rorMIzotABV+/UL6FlB9bsnnRPznPZpRO/5UHZ zdz@DESKTOP-CUOOK6S"
)

foreach ($key in $keys) {
    Add-Content $authorizedKeysPath $key
}
$step++

# Fix permissions on authorized_keys using icacls from CMD
Update-Status $step "Fixing permissions on authorized_keys using icacls from CMD..."
$icaclsCommand = "icacls `"$authorizedKeysPath`" /inheritance:r /grant:r ansible:(R) /grant:r `"NT AUTHORITY\SYSTEM`":(F) /grant:r `"BUILTIN\Administrators`":(F)"
cmd.exe /c $icaclsCommand
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

# URL to OpenSSHUtils zip file
Update-Status $step "Downloading and extracting OpenSSHUtils..."
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win32.zip"
$zipPath = "$env:TEMP\OpenSSHUtils.zip"
$extractPath = "$env:ProgramFiles\OpenSSHUtils"

# Download the OpenSSHUtils zip file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

# Extract the zip file
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Import the OpenSSHUtils module
Import-Module "$extractPath\OpenSSH-Win32\OpenSSHUtils.psd1" -Force

# Repair permissions on authorized_keys
Update-Status $step "Repairing permissions on authorized_keys..."
Repair-AuthorizedKeyPermission -FilePath C:\Users\ansible\.ssh\authorized_keys
$step++

# Final restart of SSH service to apply any changes
Update-Status $step "Final restart of OpenSSH service..."
Restart-Service sshd
$step++

Write-Output "Setup complete." 
