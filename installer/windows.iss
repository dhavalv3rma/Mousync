; Inno Setup script - builds MouseBridge-Setup.exe
[Setup]
AppName=MouseBridge
AppVersion=1.0
AppPublisher=Dhaval Verma
DefaultDirName={autopf}\MouseBridge
DefaultGroupName=MouseBridge
UninstallDisplayIcon={app}\MouseBridge.exe
OutputDir=..\Output
OutputBaseFilename=MouseBridge-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "startup"; Description: "Start MouseBridge automatically when Windows starts"; Flags: unchecked

[Files]
Source: "..\dist\MouseBridge.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\MouseBridge"; Filename: "{app}\MouseBridge.exe"
Name: "{group}\Uninstall MouseBridge"; Filename: "{uninstallexe}"
Name: "{autodesktop}\MouseBridge"; Filename: "{app}\MouseBridge.exe"; Tasks: desktopicon
Name: "{userstartup}\MouseBridge"; Filename: "{app}\MouseBridge.exe"; Parameters: "--autostart"; Tasks: startup

[Run]
; open the firewall port on private networks so the two PCs can connect
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""MouseBridge"" dir=in action=allow protocol=TCP localport=24850 profile=private"; Flags: runhidden
Filename: "{app}\MouseBridge.exe"; Description: "Launch MouseBridge"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MouseBridge"""; Flags: runhidden; RunOnceId: "DelFirewall"
