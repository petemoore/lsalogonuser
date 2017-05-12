// ConsoleApplication1.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
using namespace std;


// see below for definitions of these
size_t wcsByteLen(const wchar_t* str);
void InitUnicodeString(UNICODE_STRING& str, const wchar_t* value, BYTE* buffer, size_t& offset);


struct hexdump {
	void const* data;
	int len;

	hexdump(void const* data, int len) : data(data), len(len) {}

	template<class T>
	hexdump(T const& v) : data(&v), len(sizeof v) {}

	friend
		std::ostream& operator<<(std::ostream& s, hexdump const& v) {
		// don't change formatting for s
		std::ostream out(s.rdbuf());
		out << std::hex << std::setfill('0');

		unsigned char const* pc = reinterpret_cast<unsigned char const*>(v.data);

		std::string buf;
		buf.reserve(17); // premature optimization

		printf("%p:\n", (void *)pc);

		int i;
		for (i = 0; i < v.len; ++i, ++pc) {
			if ((i % 16) == 0) {
				if (i) {
					out << "  " << buf << '\n';
					buf.clear();
				}
				out << "  " << std::setw(4) << i << ' ';
			}

			out << ' ' << std::setw(2) << unsigned(*pc);
			buf += (0x20 <= *pc && *pc <= 0x7e) ? *pc : '.';
		}
		if (i % 16) {
			char const* spaces16x3 = "                                                ";
			out << &spaces16x3[3 * (i % 16)];
		}
		out << "  " << buf << '\n';

		return s;
	}
};

int main(int argc, char * argv[])
{

	// connect to the LSA
	HANDLE lsa;
	LsaConnectUntrusted(&lsa);

	const wchar_t* domain = L"";
	const wchar_t* user = L"someuser";
	const wchar_t* password = L"qwertQWERT123";

	// prepare the authentication info
	ULONG authInfoSize = sizeof(KERB_INTERACTIVE_LOGON) +
		wcsByteLen(domain) + wcsByteLen(user) + wcsByteLen(password);
	BYTE* authInfoBuf = new BYTE[authInfoSize];
	KERB_INTERACTIVE_LOGON* authInfo = (KERB_INTERACTIVE_LOGON*)authInfoBuf;
	authInfo->MessageType = KerbInteractiveLogon;
	size_t offset = sizeof(KERB_INTERACTIVE_LOGON);
	InitUnicodeString(authInfo->LogonDomainName, domain, authInfoBuf, offset);
	InitUnicodeString(authInfo->UserName, user, authInfoBuf, offset);
	InitUnicodeString(authInfo->Password, password, authInfoBuf, offset);

	// find the Negotiate security package
	char packageNameRaw[] = MICROSOFT_KERBEROS_NAME_A;
	LSA_STRING packageName;
	packageName.Buffer = packageNameRaw;
	packageName.Length = packageName.MaximumLength = (USHORT)strlen(packageName.Buffer);
	ULONG packageId;
	LsaLookupAuthenticationPackage(lsa, &packageName, &packageId);

	// create a dummy origin and token source
	LSA_STRING origin = {};
	origin.Buffer = _strdup("TestAppFoo");
	origin.Length = (USHORT)strlen(origin.Buffer);
	origin.MaximumLength = origin.Length;
	TOKEN_SOURCE source = {};
	strcpy(source.SourceName, "foobar");
	AllocateLocallyUniqueId(&source.SourceIdentifier);

	void* profileBuffer;
	DWORD profileBufLen;
	LUID luid;
	HANDLE token;
	QUOTA_LIMITS qlimits;
	NTSTATUS subStatus;
	PTOKEN_GROUPS localGroups = 0;

	std::cout << "&lsaHandle:\n" << hexdump(lsa);
	std::cout << "&originName:\n" << hexdump(&origin);
	std::cout << "originName:\n" << hexdump(origin);
	std::cout << "originName.Buffer:\n" << hexdump(*(origin.Buffer));
	std::cout << "&logonType:\n" << hexdump(Interactive);
	std::cout << "&authenticationPackage:\n" << hexdump(packageId);
	std::cout << "&authenticationInformation:\n" << hexdump(authInfo);
	std::cout << "authenticationInformation:\n" << hexdump(*authInfo);
	std::cout << "authenticationInformation.LogonDomainName.Buffer:\n" << hexdump(*((*authInfo).LogonDomainName.Buffer));
	std::cout << "authenticationInformation.UserName.Buffer:\n" << hexdump(*((*authInfo).UserName.Buffer));
	std::cout << "authenticationInformation.Password.Buffer:\n" << hexdump(*((*authInfo).Password.Buffer));
	std::cout << "&authenticationInformationLength:\n" << hexdump(authInfoSize);
	std::cout << "&localGroups:\n" << hexdump(localGroups);
	std::cout << "&sourceContext:\n" << hexdump(&source);
	std::cout << "sourceContext:\n" << hexdump(source);
	std::cout << "&profileBuffer:\n" << hexdump(&profileBuffer);
	std::cout << "profileBuffer:\n" << hexdump(profileBuffer);
	std::cout << "&profileBufferLength:\n" << hexdump(&profileBufLen);
	std::cout << "profileBufferLength:\n" << hexdump(profileBufLen);
	std::cout << "&logonId:\n" << hexdump(&luid);
	std::cout << "logonId:\n" << hexdump(luid);
	std::cout << "&token:\n" << hexdump(&token);
	std::cout << "token:\n" << hexdump(token);
	std::cout << "&quotas:\n" << hexdump(&qlimits);
	std::cout << "quotas:\n" << hexdump(qlimits);
	std::cout << "&subStatus:\n" << hexdump(&subStatus);
	std::cout << "subStatus:\n" << hexdump(subStatus);


	NTSTATUS status = LsaLogonUser(lsa, &origin, Interactive, packageId,
		authInfo, authInfoSize, localGroups, &source, &profileBuffer, &profileBufLen,
		&luid, &token, &qlimits, &subStatus);
	if (status != ERROR_SUCCESS)
	{
		printf("LsaLogonUser failed: %x\n", status);
		ULONG err = LsaNtStatusToWinError(status);
		printf("err: %x\n", err);
		return 1;
	}
	printf("Done\n");
}

size_t wcsByteLen(const wchar_t* str)
{
	return wcslen(str) * sizeof(wchar_t);
}

void InitUnicodeString(UNICODE_STRING& str, const wchar_t* value, BYTE* buffer, size_t& offset) {
	size_t size = wcsByteLen(value);
	str.Length = str.MaximumLength = (USHORT)size;
	str.Buffer = (PWSTR)(buffer + offset);
	memcpy(str.Buffer, value, size);
	offset += size;
}
