[Setup]
AppName=VPS Studio
AppVersion=0.2.0
AppPublisher=Caesars Network LLC
AppCopyright=Copyright © 2026 Caesars Network LLC
DefaultDirName={autopf}\VPS Studio
DefaultGroupName=VPS Studio
OutputBaseFilename=VPS-Studio-v0.2.0-Setup
OutputDir=final\releases
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
VersionInfoCopyright=Copyright © 2026 Caesars Network LLC
SetupIconFile=icons\icon.ico
UninstallDisplayIcon={app}\vps-studio.exe

[Files]
Source: "final\releases\vps-studio.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VPS Studio"; Filename: "{app}\vps-studio.exe"
Name: "{group}\Uninstall VPS Studio"; Filename: "{uninstallexe}"
Name: "{autodesktop}\VPS Studio"; Filename: "{app}\vps-studio.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
