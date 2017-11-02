#include <iostream>
#include "./../grpcBE/grpcBE.h"
#pragma comment(lib, "./../x64/Release/grpcBE.lib")

std::string copystr(std::string s) {
	return s;
}


int main() {
	
	Load();
	PWCHAR reason;
	wchar_t code[] = L"123456";
	std::cout << "6 digit pin?>";
	std::wcin>> code;
	int res = CheckTOTP(L"dev", NULL, code, &reason);


	
}