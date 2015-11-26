#include-once
#include <Crypt.au3>

;; http://www.autoitscript.com/forum/topic/145556-solved-hmac-sha1/?p=1028830
Func _HMAC_SHA1($key, $message)
    If Not IsBinary($key) Then $key = Binary($key)
    If Not IsBinary($message) Then $message = Binary($message)
    Local $blocksize = 64
    Local $a_opad[$blocksize], $a_ipad[$blocksize]
    Local Const $oconst = 0x5C, $iconst = 0x36
    Local $opad = Binary(''), $ipad = Binary('')
    If BinaryLen($key) > $blocksize Then $key = _Crypt_HashData($key, $CALG_SHA1)
    For $i = 1 To BinaryLen($key)
        $a_ipad[$i-1] = Number(BinaryMid($key, $i, 1))
        $a_opad[$i-1] = Number(BinaryMid($key, $i, 1))
    Next
    For $i = 0 To $blocksize - 1
        $a_opad[$i] = BitXOR($a_opad[$i], $oconst)
        $a_ipad[$i] = BitXOR($a_ipad[$i], $iconst)
    Next
    For $i = 0 To $blocksize - 1
        $ipad &= Binary('0x' & Hex($a_ipad[$i], 2))
        $opad &= Binary('0x' & Hex($a_opad[$i], 2))
    Next
    Return _Crypt_HashData($opad & _Crypt_HashData($ipad & $message, $CALG_SHA1), $CALG_SHA1)
EndFunc

Func _HMAC_MD5($key, $message)
    If Not IsBinary($key) Then $key = Binary($key)
    If Not IsBinary($message) Then $message = Binary($message)
    Local $blocksize = 64
    Local $a_opad[$blocksize], $a_ipad[$blocksize]
    Local Const $oconst = 0x5C, $iconst = 0x36
    Local $opad = Binary(''), $ipad = Binary('')
    If BinaryLen($key) > $blocksize Then $key = _Crypt_HashData($key, $CALG_MD5)
    For $i = 1 To BinaryLen($key)
        $a_ipad[$i-1] = Number(BinaryMid($key, $i, 1))
        $a_opad[$i-1] = Number(BinaryMid($key, $i, 1))
    Next
    For $i = 0 To $blocksize - 1
        $a_opad[$i] = BitXOR($a_opad[$i], $oconst)
        $a_ipad[$i] = BitXOR($a_ipad[$i], $iconst)
    Next
    For $i = 0 To $blocksize - 1
        $ipad &= Binary('0x' & Hex($a_ipad[$i], 2))
        $opad &= Binary('0x' & Hex($a_opad[$i], 2))
    Next
    Return _Crypt_HashData($opad & _Crypt_HashData($ipad & $message, $CALG_MD5), $CALG_MD5)
EndFunc