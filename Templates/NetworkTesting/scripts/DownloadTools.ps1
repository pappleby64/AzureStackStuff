$NTttcp = 'https://gallery.technet.microsoft.com/NTttcp-Version-528-Now-f8b12769/file/159655/1/NTttcp-v5.33.zip'
New-Item 'C:\tools' -type Directory -Force
Start-BitsTransfer -Source $NTttcp -Destination 'c:\tools\NTttcp.zip'
Expand-Archive c:\tools\NTttcp.zip -DestinationPath c:\tools
