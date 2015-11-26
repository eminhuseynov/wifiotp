#RequireAdmin
#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Icon=logo.ico
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****
#include-once
#include <_HMAC.au3>
#include <Date.au3>
Global $key = IniRead("wifiotpserver.ini", "WifiOTPServer", "EncryptionKey", "no") ; "3244234234";
Global $secret = IniRead("wifiotpserver.ini", "WifiOTPServer", "TOTPSecret", "no") ; "JBSWY3DPEHPK3PXP";
Global $WIFIID=IniRead("wifiotpserver.ini", "WifiOTPServer", "WifiID", "WOTP_")
Global $BROADCASTED
Global $tCounter=0




;; http://tools.ietf.org/html/rfc6238
Func _GenerateTOTP($key, $keyIsBase32 = True, $time = Default, $period = 30, $digits = 6)
    Local $DIGITS_POWER[9] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
    ; time is some number of seconds
    If $time = Default Then $time = _GetUnixTimeUTC()
    $time = StringFormat("%016X", Floor($time / $period))
    If $keyIsBase32 Then
        $key = _Base32ToHex($key, True) ; return binary
    Else
        $key = StringToBinary($key)
    EndIf
    ; HMAC function expects binary arguments
    Local $hash = _HMAC_SHA1($key, Binary("0x" & $time))
    Local $offset = BitAND(BinaryMid($hash, BinaryLen($hash), 1), 0xf)
    Local $otp = BitOR(BitShift(BitAND(BinaryMid($hash, $offset + 1, 1), 0x7f), -24), _
            BitShift(BitAND(BinaryMid($hash, $offset + 2, 1), 0xff), -16), _
            BitShift(BitAND(BinaryMid($hash, $offset + 3, 1), 0xff), -8), _
            BitAND(BinaryMid($hash, $offset + 4, 1), 0xff) _
            )
    $otp = Mod($otp, $DIGITS_POWER[$digits])
    Return StringFormat("%0" & $digits & "i", $otp)
EndFunc

;; http://www.autoitscript.com/forum/topic/153617-seconds-since-epoch-aka-unix-timestamp/
Func _GetUnixTimeUTC()
    ; returns number of seconds since EPOCH in UTC
    Local $aSysTimeInfo = _Date_Time_GetTimeZoneInformation()
    Local $utcTime = ""
    Local $sDate = _NowCalc()
    If $aSysTimeInfo[0] = 2 Then
        $utcTime = _DateAdd('n', $aSysTimeInfo[1] + $aSysTimeInfo[7], $sDate)
    Else
        $utcTime = _DateAdd('n', $aSysTimeInfo[1], $sDate)
    EndIf
    Return _DateDiff('s', "1970/01/01 00:00:00", $utcTime)
EndFunc

;; http://tomeko.net/online_tools/base32.php?lang=en
Func _Base32ToHex($sInput, $returnBinary = False)
    $sInput = StringRegExpReplace(StringUpper($sInput), "[^A-Z2-7]", "")
    Local $key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    Local $buffer = 0, $bitsLeft = 0, $i = 0, $count = 0, $output = "", $val
    While $i < StringLen($sInput)
        $val = StringInStr($key, StringMid($sInput, $i + 1, 1)) - 1 ; StringInStr returns 1 as 1st position
        If $val >=0 And $val < 32 Then
            $buffer = BitOR(BitShift($buffer, -5), $val)
            $bitsLeft += 5
            If $bitsLeft >= 8 Then
                $output &= Chr(BitAND(BitShift($buffer, $bitsLeft - 8), 0xFF))
                $bitsLeft -= 8
            EndIf
        EndIf
        $i += 1
    WEnd
    If $bitsLeft > 0 Then
        $buffer = BitShift($buffer, -5)
        $output &= Chr(BitAND(BitShift($buffer, $bitsLeft - 3), 0xFF))
    EndIf
    If $returnBinary Then
        Return StringToBinary($output)
    Else
        Return $output
    EndIf
EndFunc

#cs
Alternate base32 to hex functions
Func _b32toh($input)
    $input = StringRegExpReplace(StringUpper($input), "[^A-Z2-7]", "")
    Local $ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    Local $bits = "", $hex = "", $val, $i
    For $i = 0 To StringLen($input) - 1
        $val = StringInStr($ch, StringMid($input, $i + 1, 1)) - 1
        $bits &= StringFormat("%05s", _itob($val))
    Next
    $i = 0
    Local $chunk
    While ($i + 4) <= StringLen($bits)
        $chunk = StringMid($bits, $i + 1, 4)
        $hex &= StringFormat("%X", _btoi($chunk))
        $i += 4
    WEnd
    Return $hex
EndFunc

; int to binary (0's and 1's) string
Func _itob($int)
    Local $o = ""
    While $int
        $o = BitAND($int, 1) & $o
        $int = BitShift($int, 1)
    WEnd
    Return $o
EndFunc

; binary (0's and 1's) string to int
Func _btoi($b)
    Local $p = 0, $o = 0
    For $i = StringLen($b) To 1 Step -1
        $o += (2 ^ $p) * Number(StringMid($b, $i, 1))
        $p += 1
    Next
    Return $o
EndFunc
#ce

Func _TOTPTestVectors()
#cs
   Test vectors operate in HOTP mode.

   The test token shared secret uses the ASCII string value
   "12345678901234567890".  With Time Step X = 30, and the Unix epoch as
   the initial value to count time steps, where T0 = 0, the TOTP
   algorithm will display the following values for specified modes and
   timestamps.

  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+
#ce
    Local $times[6] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
    For $i = 0 To 5
        ConsoleWrite(StringFormat("%016X", Floor($times[$i] / 30)) & " : " & _
            _GenerateTOTP("12345678901234567890", False, $times[$i], 30, 8) & @CRLF)
    Next
EndFunc




#include <GUIConstantsEx.au3>

#region GUI
Opt("GUIOnEventMode", 1)

Global $hGUI = 0
Local $iButton1 = 0 ;, $iButton2 = 0

$hGUI = GUICreate("WiFiOTP Server", 400, 70, 351, 254)
GUISetOnEvent($GUI_EVENT_CLOSE, "_Exit")
$label = GUICtrlCreateLabel("Starting... ", 10, 20, 400, 25)
GUICtrlSetFont($label, Default, 600)

Local $label2 = GUICtrlCreateLabel("WiFiOTP Demo. Please allow 2-3 seconds for wifi scan to complete on the client", 10, 50, 400, 25)

GUISetState(@SW_SHOW, $hGUI)
#endregion GUI

Global $blPaused = False

While 1

    Local $totpOTP= _GenerateTOTP($secret)
	Local $encTOTP= StringTrimLeft ( rc4($key, $totpOTP),2)



;run netsh if needed

if ($BROADCASTED<>$encTOTP) Then
$BROADCASTED=	$encTOTP
;MsgBox(0,"netsh "&$WIFIID&$encTOTP,"netsh "&$WIFIID&$encTOTP);

;Change counter
if ($tCounter>=99999) Then
$tCounter=0
EndIf
$tCounter=$tCounter+1

Local $batfile="netsh.exe wlan stop hostednetwork "&@CRLF&"netsh.exe wlan set hostednetwork mode=allow ssid="&$WIFIID&$encTOTP&"_"&$tCounter&" key=%RANDOM%%RANDOM% "&@CRLF&"netsh.exe wlan start hostednetwork"
Local $hFileOpen = FileOpen(@TempDir&"\wifiotpserver.bat", $FO_OVERWRITE)

FileWrite($hFileOpen, $batfile)
FileClose($hFileOpen)
$f = RunWait (@TempDir&"\wifiotpserver.bat",@TempDir,@SW_HIDE)



GUICtrlSetData ($label, "Sending OTP "& $totpOTP & " as '"&$WIFIID&$encTOTP&"_"&$tCounter&"'")

EndIf



Sleep(5000)
WEnd



Func _Exit()
    GUIDelete($hGUI)
    Exit
EndFunc   ;==>_Exit


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