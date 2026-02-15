; NovaVPN — Inno Setup Installer Script
; Для сборки: iscc.exe /DMyAppVersion=3.0.0 novavpn.iss
; Версия передаётся из build-v2.bat через /D, ниже — fallback

#define MyAppName "NovaVPN"
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppPublisher "NovaVPN"
#define MyAppURL "https://novavpn.app"
#define MyAppExeName "NovaVPN.exe"
#define MyServiceExeName "novavpn-service.exe"

[Setup]
AppId={{B7E2F8A1-3C4D-4E5F-9A6B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
; Требуем права администратора (сервис не работает без админа, выбор без-админ отключён)
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=NovaVPN-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
MinVersion=10.0
UsePreviousAppDir=yes
; Закрывать запущенное приложение при установке/деинсталляции
CloseApplications=force
CloseApplicationsFilter=*.exe
AppMutex=NovaVPN_AppMutex
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=..\..\assets\logo.ico
; Архитектура
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Подавляем предупреждение о per-user areas (автозагрузка и очистка — ок для per-user)
UsedUserAreasWarning=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Запускать NovaVPN при входе в Windows"; GroupDescription: "Дополнительно:"

[Files]
; Основные файлы
Source: "..\dist\NovaVPN\NovaVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\NovaVPN\novavpn-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\NovaVPN\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\assets\logo.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\logo.ico"
Name: "{group}\Удалить {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\logo.ico"; Tasks: desktopicon

[Registry]
; Автозапуск (если выбрано)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NovaVPN"; ValueData: """{app}\{#MyAppExeName}"" -autostart"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Устанавливаем и запускаем сервис после установки
Filename: "{app}\{#MyServiceExeName}"; Parameters: "install"; StatusMsg: "Устанавливаю сервис NovaVPN..."; Flags: runhidden waituntilterminated
; Предложить запустить приложение
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Останавливаем и удаляем сервис при деинсталляции
Filename: "{app}\{#MyServiceExeName}"; Parameters: "stop"; RunOnceId: "StopService"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyServiceExeName}"; Parameters: "uninstall"; RunOnceId: "UninstallService"; Flags: runhidden waituntilterminated

[UninstallDelete]
; Очищаем логи и конфиги
Type: filesandordirs; Name: "{commonappdata}\NovaVPN"
Type: filesandordirs; Name: "{localappdata}\NovaVPN"

[Code]
// Принудительно завершаем NovaVPN.exe через taskkill
procedure KillNovaVPN;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM NovaVPN.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
end;

// Перед установкой/обновлением: завершаем GUI, останавливаем и удаляем старый сервис
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  // Завершаем GUI если запущен
  KillNovaVPN;
  // Останавливаем сервис если он запущен
  Exec(ExpandConstant('{app}\{#MyServiceExeName}'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Удаляем старый сервис
  Exec(ExpandConstant('{app}\{#MyServiceExeName}'), 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Пауза чтобы файлы освободились
  Sleep(1500);
end;

// Перед деинсталляцией: завершаем GUI, останавливаем сервис
function InitializeUninstall: Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Завершаем GUI
  KillNovaVPN;
  // Останавливаем сервис
  Exec(ExpandConstant('{app}\{#MyServiceExeName}'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

// После деинсталляции: убираем автозагрузку
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'NovaVPN');
  end;
end;
