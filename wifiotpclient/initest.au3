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

$sData = "123456"
$sKey = "3244234234"
$dCrypt ="0x6ACAC3402EEC"
$bCrypt = rc4($sKey, $sData) ;Encrypt
$bDcrypt = rc4($sKey, $dCrypt) ;decrypt

$sDcrypt = BinaryToString($bDcrypt)
$bData = StringToBinary($sDcrypt)
$reCrypt = rc4($sKey, $bData)
$srecrypt = $bCrypt
ConsoleWrite( $bCrypt&@CRLF&$bDcrypt&@CRLF&$sDcrypt&@CRLF&$bData&@CRLF&$reCrypt&@CRLF&$srecrypt)

