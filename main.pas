unit main;
//Scan Signature
//https://www.unknowncheats.me/forum/rules-of-survival/265128-scan-signature-v1.html
interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,SigScan, Vcl.ComCtrls,
  Vcl.Imaging.pngimage, Vcl.ExtCtrls;
type
  PProcessID = ^TProcessID;
  TProcessID = record
    PID : Integer;
    Title : String[255];
  end;
type
  TForm1 = class(TForm)
    mmLog: TMemo;
    btnScan: TButton;
    Progress: TProgressBar;
    Image1: TImage;
    procedure btnScanClick(Sender: TObject);
  private
    { Private declarations }
  public
   procedure doProcess; { Public declarations }
  end;

var
  Form1: TForm1;
  Mem:TSigScan;
implementation
{$R *.dfm}

function EnumProcess(Handle: HWND; lParam: Integer): BOOL; stdcall;
var
  PID : Cardinal;
  ProcessID : TProcessID;
  Title : String;
begin
  If Handle = NULL Then
    begin
    Result := False;
  end
  Else
    begin
    ProcessID := PProcessID(Pointer(lParam))^;
    GetWindowThreadProcessID(Handle,PID);
    If ProcessID.PID = lParam Then
      begin
      SetLength(Title,255);
      SetLength(Title,GetWindowText(Handle,PChar(Title),Length(Title)));
      If Title = '' Then
        begin
        Title := 'Empty';
      end;
      ProcessID.Title := Title;
    end;
    Result := True;
  end;
end;
function GetWindowNameFromPID(PID: Integer): String;
var
  ProcessID : PProcessID;
begin
  GetMem(ProcessID,SizeOf(TProcessID));
  ProcessID^.PID := PID;
 If Not EnumWindows(@EnumProcess,Integer(Pointer(ProcessID))) Then
    begin
    If MessageDlg('Could not get hook to the process handles.' + #13#10 + 'Try Again?',mtConfirmation,[mbYes,mbNo],0) = mrYes Then
      begin
      GetWindowNameFromPID(PID);
    end;
  end;
end;


procedure TForm1.doProcess;
var
  title : array[0..254] of Char;
  HW:Cardinal;
  s : string;
begin
  mmLog.Clear;
  mmLog.Lines.Add('Please wait...');
  Progress.Position := 0;
  Mem.GetPID();
  if (m_pID <> 0) then
  begin

        Progress.StepBy(5);
         module := Mem.GetModuleInfo(nil, true);
        m_hProc := OpenProcess(PROCESS_ALL_ACCESS, false, m_pID);
        HW:= Sig.GetHWndByProgramName('ros.exe');

        GetWindowText(HW,title,sizeof(title));
        s:= title;
        mmLog.Lines.Add('Target Process...');
        mmLog.Lines.Add(' Process Name : ros.exe');
        mmLog.Lines.Add(' Window Name : '+ String(s));
        mmLog.Lines.Add(' Handle Process : $'+ inttohex(m_hProc, sizeof(m_hProc)));
        mmLog.Lines.Add(' Process ID : $'+ inttohex(m_pID, sizeof(m_pID)));
        mmLog.Lines.Add(' Base Address : $'+ inttohex(integer(module.modBaseAddr), sizeof(module.modBaseAddr)));
        mmLog.Lines.Add(' Base Size : $'+ inttohex(module.modBaseSize, sizeof(module.modBaseSize)));

         mmLog.Lines.Add('Scanning Localplayer Offset...');
        m_SignLocalPlayer := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignLocalPlayer, MaskLocalPlayer);
         Progress.StepBy(10);
          mmLog.Lines.Add('Scanning Client Offset...');
        m_SignClient := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignClient, MaskClient);
         Progress.StepBy(10);
          mmLog.Lines.Add('Scanning Render Offset...');
        m_SignRender := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignRender, MaskRender);
         Progress.StepBy(10);
         mmLog.Lines.Add('Scanning ViewMatrix Offset...');
        m_SignViewMatrix := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignViewMatrix, MaskViewMatrix);
          Progress.StepBy(10);
          mmLog.Lines.Add('Scanning SceneContext Offset...');
        m_SignSceneContext := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignViewMatrix, MaskViewMatrix);
           Progress.StepBy(10);
           mmLog.Lines.Add('Scanning Wallthrough Offset...');
        m_SignWall := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignWall, MaskWall);
          Progress.StepBy(10);
          mmLog.Lines.Add('Scanning CarSpeed Offset...');
        m_SignCarSpeed := Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignCarSpeed, MaskCarSpeed);
           Progress.StepBy(10);
           mmLog.Lines.Add('Scanning Zoom Offset...');
        m_SignZoomHack:=Mem.ScanSignature(integer(module.modBaseAddr), module.modBaseSize, @SignZoomHack, MaskZoomHack);
        Progress.StepBy(10);
        mmLog.Clear;
        mmLog.Lines.Add(' Window Name : '+ String(s));
        mmLog.Lines.Add(' Handle Process : $'+ inttohex(m_hProc, sizeof(m_hProc)));
        mmLog.Lines.Add(' Process ID : $'+ inttohex(m_pID, sizeof(m_pID)));
        mmLog.Lines.Add(' Base Address : $'+ inttohex(integer(module.modBaseAddr), sizeof(module.modBaseAddr)));
        mmLog.Lines.Add(' Base Size : $'+ inttohex(module.modBaseSize, sizeof(module.modBaseSize)));
        mmLog.Lines.Add('Const');
        mmLog.Lines.Add(' LocalPlayer = $'+ inttohex(m_SignLocalPlayer - integer(module.modBaseAddr), sizeof(m_SignLocalPlayer)));
        mmLog.Lines.Add(' Client = $'+ inttohex(m_SignClient - integer(module.modBaseAddr), sizeof(m_SignClient)));
        mmLog.Lines.Add(' Render = $'+ inttohex(m_SignRender - integer(module.modBaseAddr), sizeof(m_SignRender)));
        mmLog.Lines.Add(' ViewMatrix = $'+ inttohex(m_SignViewMatrix - integer(module.modBaseAddr)- $4A8, sizeof(m_SignViewMatrix)));
        mmLog.Lines.Add(' SceneContext = $'+ inttohex(m_SignSceneContext - integer(module.modBaseAddr)- $4A8, sizeof(m_SignSceneContext)));
        mmLog.Lines.Add(' Wallthrough = $'+ inttohex(m_SignWall - integer(module.modBaseAddr), sizeof(m_SignWall)));
        mmLog.Lines.Add(' CarSpeed = $'+ inttohex(m_SignCarSpeed - integer(module.modBaseAddr), sizeof(m_SignCarSpeed)));
        mmLog.Lines.Add(' ZoomHack = $'+ inttohex(m_SignZoomHack - integer(module.modBaseAddr), sizeof(m_SignZoomHack)));
        Progress.StepBy(30);
        CloseHandle(m_hProc);
  end else
   mmLog.Lines.Add('Target Process not found !');
   Progress.Position := 100;
end;
procedure TForm1.btnScanClick(Sender: TObject);
var
myThread:TThread;
begin
myThread.CreateAnonymousThread(doProcess).Start;
end;

end.
