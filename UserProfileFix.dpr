program UserProfileFix;


{$APPTYPE CONSOLE}
{$WARN UNIT_PLATFORM OFF} //STFU FileCtrl Warning.
{$R UserProfileFix.res}


uses

	Registry,
	FileCtrl,
	Dialogs,
	Classes,
	Windows,
	StrUtils,
	SysUtils,
	Console in 'Console.pas';

function GetConsoleWindow: HWND; stdcall; external kernel32 name 'GetConsoleWindow';

const
	SE_BACKUP_NAME = 'SeBackupPrivilege'; // Needed for SaveKey & File Access
	SE_RESTORE_NAME = 'SeRestorePrivilege';
	SE_PRIVILEGE_DISABLED = 0;  // 0 is an assumption that works.  The default was 2012309862 I suspect that was just junk bits
{******************************************************************************
	SetTokenPrivilege
	A helper function that enables or disables specific privileges on the
	specified computer.  A NIL in SystemName means the privilege will be granted
	for the current computer.  Any other value must match the name of a computer
	on your network.
 ******************************************************************************}
procedure SetTokenPrivilege(aSystemName: PChar; aPrivilegeName: PChar; aEnabled: Boolean);
var
	TTokenHd: THandle;
	TTokenPvg: TTokenPrivileges;
	cbtpPrevious: DWORD;
	rTTokenPvg: TTokenPrivileges;
	pcbtpPreviousRequired: DWORD;
	TokenOpened, ValueFound: Boolean;
begin // SetPrivilege
	// The privilege system is only available on NT and beyond
	if (Win32Platform = VER_PLATFORM_WIN32_NT)
	then begin
		// Retrieve the Token that represents this current application session
		TokenOpened := OpenProcessToken(GetCurrentProcess(),
																		TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
																		TTokenHd);

		// Check for failure
		if (not TokenOpened)
		then raise Exception.Create('The current user does not have the access required to run this program.')
		else begin
			// Get the name of the privilege (since Windows is multi-lingual, this must be done)
			ValueFound := LookupPrivilegeValue(aSystemName, aPrivilegeName, TTokenPvg.Privileges[0].Luid) ;
			TTokenPvg.PrivilegeCount := 1;

			// Enable or disable the flag according to the bool passed
			if (aEnabled)
			then TTokenPvg.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
			else TTokenPvg.Privileges[0].Attributes := SE_PRIVILEGE_DISABLED; // See note on local constant declaration
			cbtpPrevious := SizeOf(rTTokenPvg) ;
			pcbtpPreviousRequired := 0;
			if (not ValueFound)
			then raise Exception.Create('This program is incompatible with the operating system installed on this computer.')
			else begin
				try
					// Adjust the permissions as required.
					Windows.AdjustTokenPrivileges(TTokenHd, False, TTokenPvg, cbtpPrevious,
																				rTTokenPvg, pcbtpPreviousRequired);
				except
					raise Exception.Create('The current user does not have the required access to load a registry hive.')
				end;
			end;
		end
	end;
end;  // SetPrivilege

{******************************************************************************
	GrantPrivilege
	This routine grants the privilege(s) needed to access the hidden system hive
	and load it into memory.
 ******************************************************************************}
procedure GrantPrivilege(aPrivilegeName: String);
begin // GrantPrivilege
	SetTokenPrivilege(NIL, PChar(aPrivilegeName), TRUE);
end;  // GrantPrivilege

{******************************************************************************
	RevokePrivilege
	This routine revokes privilege(s) given in GrantPrivilege
 ******************************************************************************}
procedure RevokePrivilege(aPrivilegeName: String);
begin // RevokePrivilege
	SetTokenPrivilege(NIL, PChar(aPrivilegeName), FALSE);
end;  // RevokePrivilege

const
	KEY_WOW64_64KEY=$0100;
	HiveProfilePath = '\Microsoft\Windows NT\CurrentVersion\ProfileList\';

type
	TRegInfo = Record
		Path : String;
		Tree : String;
		Remote : boolean;
		Registry : TRegistry;
		BackupKey : string;
		ProfileKey : string;
	end;

var
	RemoteHive : boolean = false;
	ProfileList : TStringList;
	RegData : TRegInfo;

function GetHiveData : TRegInfo;
var
	OfflineWinDir : string;
	idx : integer;
begin
	idx := 0;
	while not (idx in [1..3]) do
	begin
		Writeln('Please select an option');
		Writeln('1) Repair Live Registry');
		Writeln('2) Repair Offline Registry');
		Writeln('3) Exit');
		Writeln;
		Write('Select> ');
		Readln(idx);
		case idx of
		1:
			begin
				Result.Tree := '\SOFTWARE' + HiveProfilePath;
				Result.Remote := False;
			end;
		2:
			begin
				ShowMessage('Please Select the Windows Directory where the SOFTWARE hive resides');
				if SelectDirectory(OfflineWinDir,[],0) then
				begin
					if FileExists(OfflineWinDir + '\system32\config\SOFTWARE') then
					begin
						Result.Remote := True;
						Result.Path := OfflineWinDir + '\system32\config\SOFTWARE';
						Result.Tree := '\RemoteSoftware' + HiveProfilePath;
					end;
				end else
				begin
					Writeln('Remote Hive not selected');
					Result.Tree := '';
					idx := 0;
				end;
			end;
		3:
			begin
				Writeln('Done.  Press Any Key.');
				Readln;
				Halt;
			end;
		end;
	end;
end;

function LoadHive : boolean;
begin
	//Need Beyond GodMode Access here...
	Result := false;
	writeln('[INFO] Attempting to load ' + RegData.Path);
	try
		Result := RegData.Registry.Loadkey('RemoteSoftware', RegData.Path);
	finally
		if not Result then
		begin
			TextColor(12);
			writeln('[ERROR] Failed to load Remote Hive');
			TextColor(7);
		end;
	end;
end;

function GetProfileList : Boolean;
begin
	Result := false;
	ProfileList := TStringList.Create;
	//Open Key for Reading
	try
		if RegData.Registry.OpenKey(RegData.Tree, false) then
		begin
			RegData.Registry.GetKeyNames(ProfileList);
			Result := true;
		end;
	finally
		//Close Key
		RegData.Registry.CloseKey;
	end;
	If not Result then
	begin
		TextColor(12);
		writeln('[ERROR] Could Not Read ProfileList');
		TextColor(7);
	end;
end;

function FindBackupKey : boolean;
var
	idx : integer;
begin
	for idx := 0 to ProfileList.Count -1 do
	begin
		if AnsiEndsStr('.bak', ProfileList[idx]) then
		begin
			RegData.BackupKey := ProfileList[idx];
			break;
		end;
	end;
	Result := not (RegData.BackupKey = '');
	if not Result then
	begin
		TextColor(12);
		Writeln('[ERROR] Could not find a backup profile key with .bak.');
		TextColor(7);
		Writeln('[INFO] Listing Keys');
		Writeln('-------------------');
		Writeln(ProfileList.Text);
		Writeln('-------------------');
	end;
end;

function FindCurrentKey : boolean;
var
	idx : integer;
begin
	for idx := 0 to ProfileList.Count -1 do
	begin
		if ProfileList[idx] = AnsiReplaceStr(RegData.BackupKey, '.bak', '') then
		begin
			RegData.ProfileKey := ProfileList[idx];
			break;
		end;
	end;
	Result := not (RegData.ProfileKey = '');
	if not Result then
	begin
		TextColor(14);
		Writeln('[WARNING] Could not find a temporary profile key.');
		TextColor(7);
	end;
end;

function DisplayData : boolean;
var
	Data : string;
begin
	Data := '';

	Result := False;
	try
		if RegData.Registry.OpenKey(RegData.Tree+RegData.BackupKey, false) then
		begin
			Writeln('[INFO] Found the Following:');
			Data := RegData.Registry.ReadString('ProfileImagePath');
			Writeln(RegData.BackupKey + ' : ' + Data);
		end;
	finally
		RegData.Registry.CloseKey;
	end;
	if (Data = '') then
	begin
		TextColor(12);
		Writeln('[ERROR] Could not read ProfileImagePath from ' + RegData.BackupKey);
		TextColor(7);
		Exit;
	end;

	Data := ''; //Reset
	if not (RegData.ProfileKey = '') then
	begin
		try
			if RegData.Registry.OpenKey(RegData.Tree+RegData.ProfileKey, false) then
			begin
				Data := RegData.Registry.ReadString('ProfileImagePath');
				Writeln(RegData.ProfileKey + ' : ' + Data);
			end;
		finally
			RegData.Registry.CloseKey;
		end;
		if (Data = '') then
		begin
			TextColor(12);
			Writeln('[ERROR] Could not read ProfileImagePath from ' + RegData.BackupKey);
			TextColor(7);
			Exit;
		end;
	end;
	Result := true;
end;

function PromptUser(NoSwapWarning : boolean) : boolean;
var
	YN : Char;
begin
	YN := '0';
	Result := False;
	TextColor(14);
	if NoSwapWarning then
	begin
		Writeln('[WARNING] Is everything okay to switch?');
	end else
	begin
		Writeln('[WARNING] Since no temporary key was found,');
		writeln('[WARNING] Do you want to continue and restore this backup key?');
	end;
	TextColor(7);
	//while not (YN in ['y','n']) do APARENTLY NOT SAFE ANYMORE
	while not CharInSet(YN, ['y','Y','n','N']) do
	begin
		write('y/n > ');
		Readln(YN);
		case YN of
		'y': Result := True;
		'n': Result := False;
		end;
	end;
end;

function RenameKeys(SwitchMode : Boolean) : boolean;
begin
	Result := false;
	Writeln('[INFO] Renaming Keys');
	try
		if SwitchMode then
		begin
			with RegData do
			begin
				Registry.MoveKey(Tree+ProfileKey, Tree+ProfileKey + '.ba', true);
				Registry.MoveKey(Tree+BackupKey, Tree+ProfileKey, true);
				Registry.MoveKey(Tree+ProfileKey + '.ba', Tree+ProfileKey + '.bak', true);
			end;
		end else
		begin
			with RegData do
			begin
				ProfileKey := AnsiReplaceStr(BackupKey, '.bak', '');
				Registry.MoveKey(Tree+BackupKey, Tree+ProfileKey, true);
			end;
		end;
		Result := True;
	finally
		if not Result then
		begin
			TextColor(12);
			Writeln('[ERROR] SOMETHING WENT WRONG RENAMING KEYS');
			Writeln('[ERROR] NO IDEA WHY, FIX MANUALLY');
			Writeln('[.....] ...You can do that...right?');
			TextColor(7);
		end;
	end;
end;

function UpdateProfile : boolean;
begin
	Result := false;
	with RegData do
	begin
		if Registry.OpenKey(Tree+ProfileKey, false) then
		try
			Writeln('[INFO] Editing Key States');
			Registry.WriteInteger('RefCount', 0);
			Registry.WriteInteger('State', 0);
			Result := true;
		finally
			Registry.CloseKey;
			if not Result then
			begin
				TextColor(12);
				Writeln('[ERROR] Could not update set RefCount and State to 0');
				Writeln('[ERROR] on the profile.  Update manually.');
				TextColor(7);
			end;
		end else
		begin
			TextColor(12);
			Writeln('[ERROR] Could not open key to update RefCount and State');
			TextColor(7);
		end;
	end;
end;

var
	TempKeyFound : boolean;
begin
	TextColor(7);
	Console.TextBackground(0);
	ZeroMemory(@RegData, SizeOf(RegData));
	//Get Registry Info
	RegData := GetHiveData;
	//Get GODMODE Access, even in 64bit Environment
	try
		RegData.Registry := TRegistry.Create(KEY_WRITE OR KEY_WOW64_64KEY or KEY_ALL_ACCESS);
		RegData.Registry.RootKey := HKEY_LOCAL_MACHINE;
		GrantPrivilege(SE_RESTORE_NAME);

		if RegData.Remote then
		begin
			if not LoadHive then Exit; //Bail to the Finally.
		end;
		//Grab Profiles
		if not GetProfileList then Exit;
		//Find BackupKey
		if not FindBackupKey then Exit;
		//Find Current TEMP key
		TempKeyFound := FindCurrentKey;
		//Display Paths to continue (make sure not double swaping)
		if not DisplayData then Exit;
		//Prompt user to continue
		if not PromptUser(TempKeyFound) then exit;
		//Rename Keys
		if not RenameKeys(TempKeyFound) then exit;
		//Fix Real Profile
		if not UpdateProfile then exit;
	finally
		if RegData.Remote then RegData.Registry.UnLoadKey('RemoteSoftware');
		RevokePrivilege(SE_RESTORE_NAME);
		RegData.Registry.free;
		ProfileList.Free;
		TextColor(10);
		Writeln('Done. Press Any Key.');
		TextColor(7);
		Readln;
	end;

end.
