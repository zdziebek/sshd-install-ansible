# URL to OpenSSHUtils zip file
$zipUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win32.zip"
$zipPath = "$env:TEMP\OpenSSHUtils.zip"
$extractPath = "$env:ProgramFiles\OpenSSHUtils"

# Download the OpenSSHUtils zip file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

# Extract the zip file
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Import the OpenSSHUtils module
Import-Module "$extractPath\OpenSSH-Win32\OpenSSHUtils.psd1" -Force

