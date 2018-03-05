Unit SigScan;
interface

uses
  Windows, SysUtils,PSAPI, TlHelp32;
type
TSigScan = class
  public
   function ScanSignature(base: Dword; size: Dword; sign: PByte; mask: PAnsiChar): integer;
   function DataCompare(data: PByte; sign: PByte; mask: PAnsiChar): boolean;
   function GetModuleInfo(const module_name: PChar; main_process: boolean): TModuleEntry32;
   function GetHWndByProgramName(const APName: string): THandle;
   procedure GetPID;
end;
var
  Sig:TSigScan;
  m_pID: integer;
  m_hProc: THandle;
  module: TModuleEntry32;

  m_SignLocalPlayer,m_SignClient,m_SignViewMatrix,m_SignRender,m_SignSceneContext,m_SignWall,m_SignCarSpeed,m_SignZoomHack: integer;
const                              //1   2    3    4    5    6   7     8    9    10   11   12   13   14   15   16   17   18   19   20   21  22    23
  SignLocalPlayer: array [0 .. 73] of byte = ($00, $00, $00, $00, $00, $00, $00, $00, $78, $6D, $6C, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,$00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,$64,$65,$66,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$69,$6E,$74,$65,$72,$66,$61,$63,$65,$73);
  MaskLocalPlayer = '????????xxx?????????????????????????xxx?????????????????????????xxxxxxxxxx';
  SignClient: array [0 .. 50] of byte = ($00,$00,$00,$00,$00,$00,$00,$00,$69,$43,$6C,$69,$65,$6E,$74,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$74,$70,$73);
  MaskClient = '????????xxxxxxx?????????????????????????????????xxx';
  SignViewMatrix: array [0 .. 52] of byte = ($64,$79,$6E,$74,$65,$78,$2E,$64,$61,$74,$61,$5F,$70,$72,$6F,$76,$69,$64,$65,$72,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$69,$6E,$69,$74);
  MaskViewMatrix = 'xxxxxxxxxxxxxxxxxxxx?????????????????????????????xxxx';
  SignRender: array [0 .. 28] of byte = ($00,$00,$00,$00,$00,$3F,$41,$56,$4D,$65,$73,$68,$43,$6F,$6D,$6D,$61,$6E,$64,$40,$63,$6F,$63,$6F,$73,$32,$64,$40,$40);
  MaskRender = '?????xxxxxxxxxxxxxxxxxxxxxxxx';
  SignWall: array [0 .. 5] of byte = ($20,$80,$F6,$25,$20,$80);
  MaskWall = '?xxx?x';
  SignCarSpeed: array [0 .. 15] of byte = ($40,$84,$DD,$01,$0F,$C6,$C0,$00,$0F,$29,$05,$70,$33,$81,$02,$C3);
  MaskCarSpeed = 'xxxxxxx?xxxxxxxx';
  SignZoomHack: array [0 .. 15] of byte = ($E0,$FF,$54,$21,$A5,$00,$00,$80,$00,$00,$00,$00,$00,$00,$00,$00);
  MaskZoomHack = 'xxxxx??x????????';
  procName = 'ros.exe';
implementation
function GetProcessHndByHWnd(const hWnd: THandle): THandle;
var
PID: DWORD;
AhProcess: THandle;
begin
if hWnd<>0 then
begin
GetWindowThreadProcessID(hWnd, @PID);
AhProcess := OpenProcess(PROCESS_ALL_ACCESS, false, PID);
Result:=AhProcess;
CloseHandle(AhProcess);
end
else
Result:=0;
end;

// Get Process Handle By Process ID
function GetProcessHndByPID(const hAPID: THandle): THandle;
var
AhProcess: THandle;
begin
if hAPID<>0 then
begin
AhProcess := OpenProcess(PROCESS_ALL_ACCESS, false, hAPID);
Result:=AhProcess;
CloseHandle(AhProcess);
end
else
Result:=0;
end;


// Get Window Handle By ProcessID
function GetPIDByHWnd(const hWnd: THandle): THandle;
var
PID: DWORD;
begin
if hWnd<>0 then
begin
GetWindowThreadProcessID(hWnd, @PID);
Result:=PID;
end
else
Result:=0;
end;


// Get Window Handle By ProcessID
function GetHWndByPID(const hPID: THandle): THandle;
type
PEnumInfo = ^TEnumInfo;
TEnumInfo = record
ProcessID: DWORD;
HWND: THandle;
end;

function EnumWindowsProc(Wnd: DWORD; var EI: TEnumInfo): Bool; stdcall;
var
PID: DWORD;
begin
GetWindowThreadProcessID(Wnd, @PID);
Result := (PID <> EI.ProcessID) or
(not IsWindowVisible(WND)) or
(not IsWindowEnabled(WND));

if not Result then EI.HWND := WND; //break on return FALSE 所以要反向检查
end;

function FindMainWindow(PID: DWORD): DWORD;
var
EI: TEnumInfo;
begin
EI.ProcessID := PID;
EI.HWND := 0;
EnumWindows(@EnumWindowsProc, Integer(@EI));
Result := EI.HWND;
end;
begin
if hPID<>0 then
Result:=FindMainWindow(hPID)
else
Result:=0;
end;


// Get ProcessID By ProgramName (Include Path or Not Include)
function GetPIDByProgramName(const APName: string): THandle;
var
isFound: boolean;
AHandle, AhProcess: THandle;
ProcessEntry32: TProcessEntry32;
APath: array[0..MAX_PATH] of char;
begin
try
Result := 0;
AHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
ProcessEntry32.dwSize := Sizeof(ProcessEntry32);
isFound := Process32First(AHandle, ProcessEntry32);

while isFound do
begin
AhProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
false, ProcessEntry32.th32ProcessID);
GetModuleFileNameEx(AhProcess, 0, @APath[0], sizeof(APath));

if (UpperCase(StrPas(APath)) = UpperCase(APName)) or
(UpperCase(StrPas(ProcessEntry32.szExeFile)) = UpperCase(APName)) then
begin
Result := ProcessEntry32.th32ProcessID;
break;
end;
isFound := Process32Next(AHandle, ProcessEntry32);
CloseHandle(AhProcess);
end;
finally
CloseHandle(AHandle);
end;
end;
// Get Window Handle By ProgramName (Include Path or Not Include)
function TSigScan.GetHWndByProgramName(const APName: string): THandle;
begin
Result:=GetHWndByPID(GetPIDByProgramName(APName));
end;
procedure TSigScan.GetPID;
var
  snapshot: THandle;
  pInfo: PROCESSENTRY32;
begin
  snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  pInfo.dwSize := sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, pInfo)) then
  begin
        while (Process32Next(snapshot, pInfo)) do
        begin
          if pInfo.szExeFile = procName then
          begin

                m_pID := pInfo.th32ProcessID;
                CloseHandle(snapshot);
                exit;
          end;
        end;
  end;
  m_pID := 0;
  CloseHandle(snapshot);
  exit;
end;
function TSigScan.GetModuleInfo(const module_name: PChar; main_process: boolean): TModuleEntry32;
var
  snapshot: THandle;
  module: TModuleEntry32;
begin
  snapshot := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_pID);
  module.dwSize := sizeof(TModuleEntry32);
  if (Module32First(snapshot, module)) then
  begin
        if (main_process) then
        begin
          CloseHandle(snapshot);
          result := module;
        end;
        while (Module32Next(snapshot, module)) do
        begin
          if (StrIComp(PChar(ExtractFileName(module.szModule)), PChar(module_name)) = 0) then
          begin

                CloseHandle(snapshot);
                result := module;
          end;
        end;
  end;
  result := module;
end;
function TSigScan.DataCompare(data: PByte; sign: PByte; mask: PAnsiChar): boolean;
begin
  while mask^ <> #0 do
  begin
        if ((mask^ = 'x') and (data^ <> sign^)) then
        begin
          result := false;
          exit;
        end;
        inc(mask);
        inc(data);
        inc(sign);
  end;
  result := true;
end;
function TSigScan.ScanSignature(base: Dword; size: Dword; sign: PByte; mask: PAnsiChar): integer;
var
  mbi: MEMORY_BASIC_INFORMATION;
  offset: integer;
  buffer: PByte;
  BytesRead: SIZE_T;
  i: integer;
begin
  offset := 0;
  while (offset < size) do
  begin
        VirtualQueryEx(m_hProc, Pointer(base + offset), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (mbi.State <> MEM_FREE) then
        begin
          GetMem(buffer, mbi.RegionSize);
          ReadProcessMemory(m_hProc, mbi.BaseAddress, buffer, mbi.RegionSize, BytesRead);
          for i := 0 to mbi.RegionSize do
          begin
                if (DataCompare(buffer + i, sign, mask)) then
                begin
                  FreeMem(buffer);
                  result := integer(mbi.BaseAddress) + i;
                  exit;
                end;
          end;
          FreeMem(buffer);
        end;
        offset := offset + mbi.RegionSize;
  end;
  result := 0;
  end;
end.
