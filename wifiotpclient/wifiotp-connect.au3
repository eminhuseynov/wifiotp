#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=logo.ico
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include <File.au3>
#include <Misc.au3>
#include <Crypt.au3>
Global $switch = 0,$ssid,$aArray,$SSIDOTP
Global $WIFIID=IniRead("wifiotp.ini", "WifiOTP", "WifiID", "WOTP_")
Global $ScanInterval=Int(IniRead("wifiotp.ini", "WifiOTP", "ScanInterval", "30"))
Global $SubmitOnOTP=Int(IniRead("wifiotp.ini", "WifiOTP", "SubmitOnOTP", "no"))
Global $key = IniRead("wifiotp.ini", "WifiOTP", "DecryptionKey", "no") ; "3244234234";
Global $vIncrement

#include <GUIConstantsEx.au3>
#region GUI
Opt("GUIOnEventMode", 1)
 TraySetToolTip("WiFiOTP Client. Press Ctrl+Alt+X to insert current OTP") ;
Global $hGUI = 0
Local $iButton1 = 0 ;, $iButton2 = 0

$hGUI = GUICreate("WiFiOTP Client", 200, 70, 351, 254)
GUISetOnEvent($GUI_EVENT_CLOSE, "_Exit")
$label = GUICtrlCreateLabel("Starting... ", 10, 10, 160, 25)
GUICtrlSetFont($label, Default, 600)

Local $label2 = GUICtrlCreateLabel("WiFiOTP Client Demo  ", 10, 40, 200, 25)
Local $label3 = GUICtrlCreateLabel("Keyboard shortcut Ctrl+Alt+X ", 10, 55, 200, 25)
;Local $hButton = GUICtrlCreateButton("Copy",120, 15, 35, 25)

GUISetState(@SW_SHOW, $hGUI)
#endregion GUI
Func _Exit()
    GUIDelete($hGUI)
    Exit
EndFunc   ;==>_Exit

_Crypt_Startup()
$hKey = _Crypt_DeriveKey($key, $CALG_3DES)
HotKeySet("^!{x}", "reactionFunction")
readSSID()
While 1
IF Mod(@SEC,$ScanInterval) = 0 Then
        If $switch = 0 Then
            $switch = 1
	readSSID()
        EndIf
    Else
        $switch = 0
    EndIf
WEnd
Func reactionFunction()
;ConsoleWrite($SSIDOTP&";Scan"&$ScanInterval);
_SendEx("^{a}") ; send ctrl+a to replace existing text
;Decrypt broadcasted OTP
Local $str = _Crypt_DecryptData("0x"&$SSIDOTP, $hKey, $CALG_USERKEY)
Local $str=rc4($key, "0x"&$SSIDOTP)
Local $sendOTP=BinaryToString($str)
;$sendOTP=$SSIDOTP;
if ($SSIDOTP=="") Then $sendOTP="NOOTP"
_SendEx($sendOTP) ; send current OTP
Local $sendEnter=0
if $SubmitOnOTP==1 Then $sendEnter=1
if ($SSIDOTP=="") Then $sendEnter=0
if $sendEnter==1 Then _SendEx("{ENTER}")
EndFunc
Func readSSID()
;$SSIDOTP=""
;run wifiscanner.exe to refresh the ssid list
Local $tmplist=@TempDir&"\wifiotp.tmp"
ConsoleWrite($tmplist)
;Local $batfile="netsh.exe wlan show networks > "&@TempDir&"\wifiotp.txt"
;Local $hFileOpen = FileOpen(@TempDir&"\wifiotp.bat", $FO_OVERWRITE)
;FileWrite($hFileOpen, $batfile)
;FileClose($hFileOpen)

RunWait(@ScriptDir&"\wifiscanner.exe  /stext  "&$tmplist&"",@TempDir,@SW_HIDE)
;Local $batfile="netsh.exe wlan show networks > "&@TempDir&"\wifiotp.txt"
;Local $hFileOpen = FileOpen(@TempDir&"\wifiotp.bat", $FO_OVERWRITE)
;FileWrite($hFileOpen, $batfile)
;FileClose($hFileOpen)
;$f = RunWait (@TempDir&"\wifiotp.bat",@TempDir,@SW_HIDE)
$file = @TempDir&"\wifiotp.txt"
Local $ttFile=FileOpen($tmplist, 0)
$ssid=FileRead($ttFile)
FileClose($ttFile)
$aArray = StringSplit($ssid, Chr(13) )
For $i = 0 to UBound($aArray)-1
Local $iPosition = StringInStr($aArray[$i], $WIFIID)
If $iPosition>1 Then
;Checking the increment (last _ segment)
Local $vOTP=StringSplit($aArray[$i], "_" )
if (Int($vOTP[4])>=Int($vIncrement)) Then
$vIncrement=$vOTP[4]
$SSIDOTP=$vOTP[3]
Local $str=rc4($key, "0x"&$SSIDOTP)
Local $sendOTP=BinaryToString($str)
GUICtrlSetData ($label, " OTP "&$sendOTP)

EndIf
EndIf
Next
EndFunc
Func _SendEx($ss, $warn = "")
	Local $iT = TimerInit()
	While _IsPressed("10") Or _IsPressed("11") Or _IsPressed("12")
		If $warn <> "" And TimerDiff($iT) > 1000 Then
			MsgBox(262144, "Warning", $warn)
		EndIf
		Sleep(50)
	WEnd
	Send($ss)
EndFunc;==>_SendEx
Func rc4($key, $value)
    Local $S[256], $i, $j, $c, $t, $x, $y, $output
    Local $keyLength = BinaryLen($key), $valLength = BinaryLen($value)
    For $i = 0 To 255
        $S[$i] = $i
    Next
    For $i = 0 To 255
        $j = Mod($j + $S[$i] + Dec(StringTrimLeft(BinaryMid($key, Mod($i, $keyLength)+1, 1),2)),256)
        $t = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $t
    Next
    For $i = 1 To $valLength
        $x = Mod($x+1,256)
        $y = Mod($S[$x]+$y,256)
        $t = $S[$x]
        $S[$x] = $S[$y]
        $S[$y] = $t
        $j = Mod($S[$x]+$S[$y],256)
        $c = BitXOR(Dec(StringTrimLeft(BinaryMid($value, $i, 1),2)), $S[$j])
        $output = Binary($output) & Binary('0x' & Hex($c,2))
    Next
    Return $output
EndFunc
