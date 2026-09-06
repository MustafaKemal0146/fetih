; ─────────────────────────────────────────────────────────────────────────────
; FETİH Windows Native Installer (Inno Setup)
; ─────────────────────────────────────────────────────────────────────────────

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

#ifndef PublishDir
  #define PublishDir "..\..\dist\win-x64"
#endif

#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif

#ifndef OutputDir
  #define OutputDir "..\..\dist\installer"
#endif

[Setup]
AppId={{E844AC82-70F4-41A8-B6A7-7C5F5E4E3A01}}
AppName=FETİH
AppVersion={#AppVersion}
AppVerName=FETİH {#AppVersion}
AppPublisher=FETİH Project
AppPublisherURL=https://github.com/MustafaKemal0146/fetih
AppSupportURL=https://github.com/MustafaKemal0146/fetih/issues
AppUpdatesURL=https://github.com/MustafaKemal0146/fetih/releases
DefaultDirName={autopf}\Fetih
DefaultGroupName=FETİH
AllowNoIcons=yes
OutputDir={#OutputDir}
OutputBaseFilename=Fetih-Setup-{#AppVersion}-win-x64
SetupIconFile={#RepoRoot}\apps\windows\Fetih.Desktop\assets\fetih.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableWelcomePage=no

[Languages]
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
tr.DesktopShortcut=Masaüstü kısayolu oluştur
en.DesktopShortcut=Create a desktop shortcut
tr.AddToPath=FETİH komut satırı aracını PATH ortam değişkenine ekle
en.AddToPath=Add FETİH command line tool to user PATH
tr.DotNetNotice=FETİH Masaüstü .NET 10 Desktop Runtime gerektirir.
en.DotNetNotice=FETİH Desktop requires .NET 10 Desktop Runtime.

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopShortcut}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "PATH:"

[Files]
; Standalone WinUI 3 binaries
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Bundled skills catalog
Source: "{#RepoRoot}\skills\*"; DestDir: "{app}\skills"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\optional-skills\*"; DestDir: "{app}\optional-skills"; Flags: ignoreversion recursesubdirs createallsubdirs
; Python core packages and modules (required for Desktop Bridge and CLI)
Source: "{#RepoRoot}\fetih_cli\*"; DestDir: "{app}\fetih_cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\fetih_desktop_bridge\*"; DestDir: "{app}\fetih_desktop_bridge"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\agent\*"; DestDir: "{app}\agent"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\tools\*"; DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\providers\*"; DestDir: "{app}\providers"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#RepoRoot}\*.py"; DestDir: "{app}"; Flags: ignoreversion
; CLI Launcher batch
Source: "{#RepoRoot}\packaging\windows\fetih.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\FETİH"; Filename: "{app}\Fetih.Desktop.exe"; IconFilename: "{app}\assets\fetih.ico"
Name: "{group}\FETİH CLI"; Filename: "{cmd}"; Parameters: "/k ""{app}\fetih.cmd"" --help"; IconFilename: "{app}\assets\fetih.ico"
Name: "{group}\{cm:UninstallProgram,FETİH}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\FETİH"; Filename: "{app}\Fetih.Desktop.exe"; IconFilename: "{app}\assets\fetih.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\Fetih.Desktop.exe"; Description: "{cm:LaunchProgram,FETİH}"; Flags: nowait postinstall skipifsilent

[Code]
// Safely modify User PATH without duplicating or corrupting existing values
const
  EnvironmentKey = 'Environment';

procedure AddPathToEnv(PathToAdd: string);
var
  CurrentPath: string;
begin
  if RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', CurrentPath) then
  begin
    if Pos(';' + Uppercase(PathToAdd) + ';', ';' + Uppercase(CurrentPath) + ';') = 0 then
    begin
      if (CurrentPath <> '') and (CurrentPath[Length(CurrentPath)] <> ';') then
        CurrentPath := CurrentPath + ';';
      CurrentPath := CurrentPath + PathToAdd;
      RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', CurrentPath);
    end;
  end
  else
  begin
    RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', PathToAdd);
  end;
end;

procedure RemovePathFromEnv(PathToRemove: string);
var
  CurrentPath: string;
  P, L: Integer;
begin
  if RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', CurrentPath) then
  begin
    P := Pos(';' + Uppercase(PathToRemove) + ';', ';' + Uppercase(CurrentPath) + ';');
    if P > 0 then
    begin
      L := Length(PathToRemove);
      if P = 1 then
      begin
        Delete(CurrentPath, 1, L);
        if (Length(CurrentPath) > 0) and (CurrentPath[1] = ';') then
          Delete(CurrentPath, 1, 1);
      end
      else
      begin
        Delete(CurrentPath, P - 1, L + 1);
      end;
      RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', CurrentPath);
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and IsTaskSelected('addtopath') then
  begin
    AddPathToEnv(ExpandConstant('{app}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemovePathFromEnv(ExpandConstant('{app}'));
  end;
end;
