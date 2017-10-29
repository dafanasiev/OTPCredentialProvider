# OTPCredentialProvider
multiOTP Credential Provider for multiOTP supporting Windows 7/8/8.1/10/2012(R2). Also supports domain users and Microsoft Account OTP (you can read about it here http://windows.microsoft.com/en-us/windows/identity-verification-apps-faq and here https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/multiOTP)
- Forced OTP check for RDP
- Forced, optional or disabled check of OTP for local logons
- client executable of multiOTP is automatically installed and configured
- multiOTP Credential Provider is only activated if the authentication test is passed successfully
- DLL and EXE files are digitally signed
- the first strong two factor authenticaton solution that have cache support in order to work also offline!

![OTPCredentialProvider setup](https://raw.githubusercontent.com/multiOTP/OTPCredentialProvider/master/screenshots/OTPCredentialProvider-setup.png)

![OTPCredentialProvider test](https://raw.githubusercontent.com/multiOTP/OTPCredentialProvider/master/screenshots/OTPCredentialProvider-test.png)

Prerequisitions:
- installed multiOTP server(s)
- configured multiOTP user (multiOTP username = windows local account name or domain user name or microsoft account name)

Installation:
- Launch the installer (in the installer directory) and set the various parameters. You must have administrator access.

Thanks to:
- ArcadeJust ("RDP only" enhancement)
- LastSquirrelIT (first version)

Report if you have any problems or questions regarding this app.
