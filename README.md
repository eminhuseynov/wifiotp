# WifiOTP 
PERVASIVE TWO-FACTOR AUTHENTICATION USING WI-FI SSID BROADCASTS

##WifiOTP Server
As building or configuring a standalone WifiOTP Token device might be rather complex, in order to ease the validation a Windows application has been created to be used as a WifiOTP Token. Windows application is based on creating computer-to-computer (ad hoc) wireless network using “netsh hostednetwork” command. An application has been created using Autoit [15] that generates and encrypts one-time passwords and passes SSID name as an argument to netsh command. This application can run on any computer equipped with a WLAN network card and a recent Windows operating system (tested on Windows XP, Windows 7, Windows 8.x and Windows 10 Preview). The parameters, such as SSID prefix, secret shared key and encryption key are stored in an ini file.

