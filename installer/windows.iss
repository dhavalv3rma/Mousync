; Inno Setup script - builds Mousync-Setup.exe
[Setup]
AppName=Mousync
AppVersion=1.1
AppPublisher=Dhaval Verma
DefaultDirName={autopf}\Mousync
DefaultGroupName=Mousync
UninstallDisplayIcon={app}\Mousync.exe
OutputDir=..\Output
OutputBaseFilename=Mousync-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=..\assets\icon.ico

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "startup"; Description: "Start Mousync automatically when Windows starts"; Flags: unchecked

[Files]
Source: "..\dist\Mousync.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Mousync"; Filename: "{app}\Mousync.exe"
Name: "{group}\Uninstall Mousync"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Mousync"; Filename: "{app}\Mousync.exe"; Tasks: desktopicon
Name: "{userstartup}\Mousync"; Filename: "{app}\Mousync.exe"; Parameters: "--autostart"; Tasks: startup

[Run]
; remove firewall rules left by the app's previous name (harmless if absent)
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MouseBridge"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""MouseBridge Discovery"""; Flags: runhidden
; open the firewall port on private networks so the two PCs can connect
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Mousync"" dir=in action=allow protocol=TCP localport=24850 profile=private"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Mousync Discovery"" dir=in action=allow protocol=UDP localport=24851 profile=private"; Flags: runhidden
Filename: "{app}\Mousync.exe"; Description: "Launch Mousync"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Mousync"""; Flags: runhidden; RunOnceId: "DelFirewall"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Mousync Discovery"""; Flags: runhidden; RunOnceId: "DelFirewallDisc"
