program ScanSignature;

uses
  Vcl.Forms,
  main in 'main.pas' {Form1},
  SigScan in 'SigScan.pas',
  Vcl.Themes,
  Vcl.Styles;

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TStyleManager.TrySetStyle('TabletDark');
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
