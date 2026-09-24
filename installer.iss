#ifndef AppVersion
  #define AppVersion "0.3.1"
#endif
#ifndef OutputDir
  #define OutputDir "final\releases"
#endif
#ifndef OutputBaseFilename
  #define OutputBaseFilename "VPS-Studio-v0.3.1-Setup"
#endif
#ifndef SourceExe
  #define SourceExe "final\releases\vps-studio.exe"
#endif
#ifndef AppArch
  #define AppArch "x64compatible"
#endif

[Setup]
AppName=VPS Studio
AppVersion={#AppVersion}
AppPublisher=Caesars Network LLC
AppCopyright=Copyright © 2026 Caesars Network LLC
DefaultDirName={autopf}\VPS Studio
DefaultGroupName=VPS Studio
OutputBaseFilename={#OutputBaseFilename}
OutputDir={#OutputDir}
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed={#AppArch}
ArchitecturesInstallIn64BitMode={#AppArch}
VersionInfoCopyright=Copyright © 2026 Caesars Network LLC
SetupIconFile=icons\icon.ico
UninstallDisplayIcon={app}\vps-studio.exe

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "vps-studio.exe"; Flags: ignoreversion

[Icons]
Name: "{group}\VPS Studio"; Filename: "{app}\vps-studio.exe"
Name: "{group}\Uninstall VPS Studio"; Filename: "{uninstallexe}"
Name: "{autodesktop}\VPS Studio"; Filename: "{app}\vps-studio.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
