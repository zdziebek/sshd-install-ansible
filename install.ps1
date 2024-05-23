function Update-Status {
    param (
        [int]$Step,
        [string]$Message
    )
    Write-Host "[$Step/18] $Message"
}

function Generate-Password {
    $length = 16
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+"
    -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $length | ForEach-Object {[char]$_})
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

# Add user 'ansible' with a generated password
Update-Status $step "Generating password for user 'ansible'..."
$password = Generate-Password
$passwordPath = "C:\Users\ansible\password.txt"
$password | Out-File -FilePath $passwordPath
$UserPassword = ConvertTo-SecureString $password -AsPlainText -Force
$step++

Update-Status $step "Creating user 'ansible'..."
New-LocalUser -Name "ansible" -Password $UserPassword -PasswordNeverExpires -UserMayNotChangePassword
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
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfn1OEzj6GpYBxfqtJyb3UXVb4hiYmk1bSQlzX9XPY9lGkvGokstqOVWFFmFJB47TQOjB4y4ogXW17dGIbVmbzDzAz0A+Ntb+dsGiCBHNPvr5/LNTENL5kjgphWe+0BsAfBiGxRHAtKoCw83ztU2KNJEkf6ibjeiflcgzlvCUpkS/FWlTCgSn9s/igg7ueJ4+jm7UdSW99vAxBcoMoAcOzBJvQoW5VAF4kGS1b4UL3cNajLyY3sj3tcl5fjdxu4coFPnGPURdBfDDIeFL2wxy5Zghwf+npp48GlP4k/i2jnQEM0SSeCyoN42AnS6LIGVhffuFuQSNpI46dqGX+Mu25 imported-openssh-key",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO97VaxpbR4pp3eU/55Ue99Eo0nfMe8l0yK+S5KZFQ2a zdz@DESKTOP-CUOOK6S",
    "ssh-dss AAAAB3NzaC1kc3MAAACBAJZqDjjCeEMk9uwiK+9h2fRzGbDFzEJ8AG6P0zrsHp2HZkMnYsMDEoZOkRj8gCdCBet9hn69p7fDW5f4txaGDF+ZBvr8BbNXsMmYbgjljdkdxuAH+6iI2yVOOahsCtOrJG9+xrI6Cc5HU6/VtjkBZizWyUxbQbL3A4WJiY5RPKlrAAAAFQCqMNsSSEg6oElSFx4peIFFAMvsbwAAAIEAgT1QuPLT22Fz91OZw50hEOkKtJlXKCysZp0qeouojvyXxYWbWMk5kfkz6rul+jljN4ORnGrx79U5UqV8z+3G8IxLFh6121bl/rkKZBYiAF/4mA8Kn44vCxTgYlZMoGA8vcVahdL/Na28KfTotEa+FsRWxKysekSTFCSD0CRZs18AAACAbYFJEmIk6SCxBeVJHHIa5cnIYUDUzgbN7Z8SKIem/doPuQBLYJTf8uWHaM11MAUaDc1eVMp4r+ugBaZdXc7DopbVz/w9oy2ZuK2YVAG1R2Odqd9XWOly1FbXczusQuImukJZmmN9AObTiRbgc7ZfzLE9fk8wNtpTkd+KKscddJg= zdz@DESKTOP-CUOOK6S",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfn1OEzj6GpYBxfqtJyb3UXVb4hiYmk1bSQlzX9XPY9lGkvGokstqOVWFFmFJB47TQOjB4y4ogXW17dGIbVmbzDzAz0A+Ntb+dsGiCBHNPvr5/LNTENL5kjgphWe+0BsAfBiGxRHAtKoCw83ztU2KNJEkf6ibjeiflcgzlvCUpkS/FWlTCgSn9s/igg7ueJ4+jm7UdSW99vAxBcoMoAcOzBJvQoW5VAF4kGS1b4UL3cNajLyY3sj3tcl5fjdxu4coFPnGPURdBfDDIeFL2wxy5Zghwf+npp48GlP4k/i2jnQEM0SSeCyoN42AnS6LIGVhffuFuQSNpI46dqGX+Mu25 mzdziebko",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCe8U1Nu5wkiQ1i5SyCr3Fdb9Bzfyh9/Agg4sKfO9zqlspH6bmw1Y3RmiQf+aL7iv+Nj7P2ScSouRwgwO08W5YPryLSrWjTFuILHO9b1rMwraVgshYzkj3PHS4ChzA3wXAWra0aSnnjPfEBdxLmF8JazPMMQ0Dsnw7Qzytk426mnizOFNgbjYmJpox8UTEbI1Qt9YbBuEGKHWQW+2yYzZ9j9zxGSMnC0h5y7prJqyOmksZwrODxLx0yMcOYOv+dQkLNKW+igvSiFiD4UDFWvIb5llE4TSGLzS4f9NYYlLRXBdibWdUBmnojqR+MbTnlIqfaIJer8YeaCskjTSFAI3tVgFtEjQuQ3Qq0rcV/1PA1FW845JHtqPSuDSMAXTkmBLlklNk3dpPaUBr6CRdYbepSsN/+/+BNKZvRZkVC6ycJ+LdSfutXF130TYFYavc/L2DG6itJCmwlOHZDqd3/HxgLJ7ZBFLvPFdisyWHuP69sJgtpvihBvPyvFXMPcUTjU00= mzdziebko@DESKTOP-3HHGGK7"
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
