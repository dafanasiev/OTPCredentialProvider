// grpcBE.cpp : Defines the exported functions for the DLL application.
//

#include "grpcBE.h"

#include "./../OTPCredentialProvider/Logger.h"
#include "./../OTPCredentialProvider/registry.h"
#include "utf8conv.h"

#include "./grpcAPI/OTPCheckService.grpc.pb.h"
#include <grpc++/grpc++.h>
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


struct GRPC_RESPONSE
{
	int ErrorNum;
	PWSTR MessageText;
};

static const PWSTR DEFAULT_UNKNOWN_ERROR_TEXT = L"ERROR : Operation failed(and other possible unknown errors)";

static const GRPC_RESPONSE s_grpcOTPResponse[] =
{
	{ 0x00,  L"SUCCESS" },

	{ 0x01,  L"ERROR: Metadata not understood by server" },
	{ 0x02,  L"ERROR: Apikey for server not sent" },
	{ 0x03,  L"ERROR: Apikey for server is empty" },
	{ 0x04,  L"ERROR: Apikey for server is incorrect" },

	{ 0x50,  L"ERROR: OTP type not supported by server" },
	{ 0x51,  L"ERROR: Login is empty" },
	{ 0x52,  L"ERROR: Pin is empty" },

	{ 0x53,  L"ERROR: User doesn't exist" },
	{ 0x54,  L"ERROR: User locked(too many tries)" },

	{ 0x999,  L"ERROR: Authentication failed(wrong pin)" },
};


namespace api {
	class TOTPServerClient {
	public:
		TOTPServerClient(std::shared_ptr<Channel> channel, const wchar_t* apiKey)
			: stub_(OTPCheck::NewStub(channel)) {
			apiKeyU8 = utf8util::UTF8FromUTF16(apiKey);
		}

		int Check(const wchar_t* login, const wchar_t* code) {
			CheckRequest req;

			const std::string loginU8 = utf8util::UTF8FromUTF16(login);
			req.set_login(loginU8);

			const std::string codeU8 = utf8util::UTF8FromUTF16(code);
			req.set_code(codeU8);

			req.set_type(CheckRequest_OTPType_TOTP);

			ClientContext context;
			CheckResponse resp;
			context.AddMetadata("apikey", apiKeyU8);
			Status status = stub_->Check(&context, req, &resp);
			if (status.ok()) {
				PrintLn("gRPC Check call success - no error");
				return 0;
			}

			PrintLn("gRPC Check call error code: %d", status.error_code());

			int rv = -1;
			switch (status.error_code()) {
			case ::grpc::UNKNOWN:
			{
				std::string&& error_message = status.error_message();
				PrintLn("gRPC server report error (see next line)");
				PrintLn(error_message.c_str());

				if (error_message[0] == '0' && error_message[1] == 'x') {
					const char* error_messagePtr = error_message.c_str() + 2;
					rv = (int)strtol(error_messagePtr, NULL, 16);
					PrintLn("gRPC server parsed error code:%d", rv);
				}
			}
			break;
			case ::grpc::UNAVAILABLE:
				PrintLn("gRPC server unavalible : server ok?");
				break;
			default:
				break;
			}

			if (rv == 0) {
				//when error detected we MUST say callee about it (even if parse error)
				rv = -1;	//unknown error (parse respnse error, logic error, etc.)
			}
			return rv;
		}

	private:
		std::unique_ptr<OTPCheck::Stub> stub_;
		std::string apiKeyU8;
	};

}

static api::TOTPServerClient* s_client;

BE_API int __stdcall Load(void) {
	int rv;
	PWCHAR ep = NULL;
	PWCHAR epApiKey = NULL;

	try {
		bool bConfOk = true;
		if (!readRegistryConfValueString(L"grpc.endpoint", &ep, L"")) {
			PrintLn("Unable to read [grpc.endpoint] config property");
			bConfOk = false;
		}

		if (!readRegistryConfValueString(L"grpc.apikey", &epApiKey, L"")) {
			PrintLn("Unable to read [grpc.apikey] config property");
			bConfOk = false;
		}

		if (bConfOk)
		{
			const std::string epU8 = utf8util::UTF8FromUTF16(ep);
			s_client = new api::TOTPServerClient(grpc::CreateChannel(epU8, grpc::InsecureChannelCredentials()), epApiKey);
			rv = 0;
		}
		else {
			s_client = NULL;
			rv = 1;
		}
	}
	catch (std::runtime_error& er) {
		PrintLn("Exception while load");
		PrintLn(er.what());
		rv = -1;
	}
	catch (...) {
		PrintLn("Unknown cpp exception");
		rv = -1;
	}

	if (ep) CoTaskMemFree(ep);
	if (epApiKey) CoTaskMemFree(epApiKey);
	return rv;
}

BE_API int __stdcall Unload(void) {
	if (s_client != NULL) {
		delete s_client;
		s_client = NULL;
	}
	return 0;
}

BE_API int __stdcall CheckTOTP(wchar_t* login, wchar_t* prevCode, wchar_t* code, wchar_t** reason) {
	int rv;

	try {
		*reason = NULL;
		rv = s_client->Check(login, code);

		for (DWORD i = 0; i < ARRAYSIZE(s_grpcOTPResponse); i++) {
			if (s_grpcOTPResponse[i].ErrorNum - rv == 0) {
				*reason = s_grpcOTPResponse[i].MessageText;
				break;
			}
		}
		if (*reason == NULL) {
			*reason = DEFAULT_UNKNOWN_ERROR_TEXT;
		}
	}
	catch (std::runtime_error& er) {
		PrintLn("Exception while CheckTOTP");
		PrintLn(er.what());
		rv = -1;
	}
	catch (...) {
		PrintLn("Unknown cpp exception while CheckTOTP");
		rv = -1;
	}
	return rv;
}