#define _CRT_SECURE_NO_WARNINGS
#define CURL_STATICLIB
#include <windows.h>

#define CopyBytes(Dest,Src) memcpy(Dest, (BYTE*)&Src, sizeof(Src))


#pragma hdrstop

#include <math.h>
#include <cstring>
#include <cstdio>
#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <random>
#include <chrono>
#include <limits>
#include <intrin.h>


using namespace std;
void hooksend();
int SendCall();
std::string IntToHex(int value, int width);
DWORD KO_SND_FNC = 0x004A58F0;
DWORD pushdegsyo;
BYTE* packets;
size_t sizes;
void MP_AddByte(BYTE* buffer, int& offset, BYTE value);
void MP_AddShort(BYTE* buffer, int& offset, short value);
void MP_AddString(BYTE* buffer, int& offset, const std::string& str);
short Parse_GetShort(const BYTE* packets, int& offset);
void Parse_GetString(const BYTE* packets, int& offset, std::string& str, int len);
char* HashMD5(char* data, DWORD *result)
{
	DWORD dwStatus = 0;
	DWORD cbHash = 16;
	int i = 0;
	HCRYPTPROV cryptProv;
	HCRYPTHASH cryptHash;
	BYTE hash[16];
	char *hex = "0123456789abcdef";
	char *strHash;
	strHash = (char*)malloc(500);
	memset(strHash, '\0', 500);
	if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		*result = dwStatus;
		return NULL;
	}
	if (!CryptCreateHash(cryptProv, CALG_MD5, 0, 0, &cryptHash))
	{
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		*result = dwStatus;
		return NULL;
	}
	if (!CryptHashData(cryptHash, (BYTE*)data, strlen(data), 0))
	{
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		*result = dwStatus;
		return NULL;
	}
	if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hash, &cbHash, 0))
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		*result = dwStatus;
		return NULL;
	}
	for (i = 0; i < cbHash; i++)
	{
		strHash[i * 2] = hex[hash[i] >> 4];
		strHash[(i * 2) + 1] = hex[hash[i] & 0xF];
	}
	CryptReleaseContext(cryptProv, 0);
	CryptDestroyHash(cryptHash);
	return strHash;
}
#define MAILSLOT_NAME "\\\\.\\mailslot\\MyMailslot"
std::string GetWindowTitle(HWND hwnd) {
	char title[256];
	if (GetWindowText(hwnd, title, sizeof(title)) > 0) {
		return std::string(title);
	}
	return "";
}
void CleanTitleForMailslot(std::string &title) {
	for (char &c : title) {
		if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
			c = '_'; 
		}
	}
}
// EnumWindowsProc geri çaðýrma fonksiyonu
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	DWORD windowPID;
	GetWindowThreadProcessId(hwnd, &windowPID);
	if (windowPID == static_cast<DWORD>(lParam)) {
		*(HWND*)lParam = hwnd;
		return FALSE; 
	}
	return TRUE; 
}

short GenerateRandomShort() {
	unsigned seed = static_cast<unsigned>(std::chrono::system_clock::now().time_since_epoch().count());
	std::default_random_engine generator(seed);
	const int minShort = -32768;
	const int maxShort = 32767;
	std::uniform_int_distribution<int> distribution(minShort, maxShort);
	int randomValue = distribution(generator);
	return static_cast<short>(randomValue);
}


std::string GenerateRandomString(size_t length) {
	const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	static std::random_device rd;
	static std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, chars.size() - 1);

	std::string result;
	result.reserve(length);

	for (size_t i = 0; i < length; ++i) {
		result += chars[dis(gen)];
	}

	return result;
}

std::string GenerateRandomMACAddress() {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);

	std::ostringstream oss;
	for (int i = 0; i < 6; ++i) {
		if (i > 0) oss << ':';
		oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
	}

	return oss.str();
}
DWORD ReadLong(DWORD ulBase)
{
	if (!IsBadReadPtr((VOID*)ulBase, sizeof(DWORD)))
	{
		return (*(DWORD*)(ulBase));
	}
	return 0;
}
void  __declspec(naked) SendFunc()
{
	

	_asm
	{
		pushad
			mov eax, [esp + 0x24]
			mov packets, eax
			mov ebx, [esp + 0x28]
			mov sizes, ebx
			call SendCall
			mov eax, packets
			mov ebx, sizes
			mov[esp + 0x24], eax
			mov[esp + 0x28], ebx
			popad
			push - 1
			push pushdegsyo
			mov eax, KO_SND_FNC
			add eax, 7
			jmp eax
			//

	}

}
void hooked()
{
	LPCWSTR dllName = L"AVCI.soft";
	char dllNameChar[MAX_PATH];
	wcstombs(dllNameChar, dllName, MAX_PATH);
	DWORD bytes;
	HMODULE hModule = GetModuleHandle(dllNameChar);
	DWORD baseAddress = reinterpret_cast<DWORD>(hModule);
	DWORD targetAddress = baseAddress + 0x10CD40;
	BYTE jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
	DWORD jmpAddress = KO_SND_FNC + 5; 
	DWORD relativeAddress;
	if (targetAddress >= jmpAddress) {
		relativeAddress = targetAddress - jmpAddress;
	}
	else {
		relativeAddress = 0xFFFFFFFF - (jmpAddress - targetAddress) + 1;
	}
	memcpy(jmp + 1, &relativeAddress, sizeof(relativeAddress));
	memcpy((void*)KO_SND_FNC, jmp, 6);

}
void bypasstest()
{
	LPCWSTR dllName = L"Plugin.dll";
	char dllNameChar[MAX_PATH];
	wcstombs(dllNameChar, dllName, MAX_PATH);
	DWORD bytes;
	HMODULE hModule = GetModuleHandle(dllNameChar);
	DWORD baseAddress = reinterpret_cast<DWORD>(hModule);
	DWORD targetAddress = baseAddress + 0x81EB;
	BYTE jmp[] = { 0xEB, 0x25};
	memcpy((void*)targetAddress, jmp, 2);
}
void hooksend()
{
	
		pushdegsyo = ReadLong(KO_SND_FNC + 3);
		BYTE jmp[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC };
		DWORD adr = (DWORD)SendFunc;
		memcpy(jmp + 1, &adr, 4);
		pushdegsyo = ReadLong(KO_SND_FNC + 4);
		std::string result;
		for (size_t i = 0; i < sizeof(jmp); ++i)
		{
			result += IntToHex(jmp[i], 2) + " ";
		}
	//	yrk1->Label34->Caption = result;
	/*	LPCWSTR dllName = L"AVCI.soft";

		char dllNameChar[MAX_PATH];
		wcstombs(dllNameChar, dllName, MAX_PATH);

		HMODULE hModule = GetModuleHandleA(dllNameChar);
		DWORD BaseAddress = reinterpret_cast<uintptr_t>(hModule);
		DWORD FinalPointer = (DWORD)((DWORD)(BaseAddress + 0x10DEB2));*/
		memcpy((void*)KO_SND_FNC, jmp, 7);

	
}
void send(BYTE* pBuf, int len) {
	DWORD KO_PTR_PKT = 0xF368D8;
	DWORD KO_SND_FNC = 0x4A58F0;
	
	__asm{
		MOV ECX, KO_PTR_PKT
			MOV ECX, DWORD PTR DS : [ECX]
			PUSH len
			PUSH pBuf
			MOV EAX, KO_SND_FNC
			CALL EAX
	}

}
std::string IntToHex(int value, int width) {
	std::stringstream ss;
	ss << std::hex << std::setw(width) << std::setfill('0') << value;
	return ss.str();
}

// Ana fonksiyon
int SendCall() {
	// Deðiþkenlerin baþlatýlmasý
	
	// Hex string oluþturma
	std::string hex;
	bool antiban = false;
	int yrk = 1;

	for (size_t i = 0; i < sizes; i++) {
		hex += IntToHex(static_cast<int>(packets[i]), 2);
	}

	
	bool checkboxChecked = true; 
	if (checkboxChecked) {
		std::string szAccid;
		std::string passwrd;
		std::string pcname2;


		if (packets[0] == 0x01) {
			short vala = GenerateRandomShort();
			short valb = GenerateRandomShort();
			short valc = GenerateRandomShort();
			short valx = 1;
			std::string pcname = GenerateRandomString(6);
			std::string maczaddr = GenerateRandomMACAddress();
			BYTE byBuff[128] = { 0 }; 
			int iOffset = 0;

			int iLen = Parse_GetShort(packets, yrk);
			Parse_GetString(packets, yrk, szAccid, iLen);

			int iLen2 = Parse_GetShort(packets, yrk);
			Parse_GetString(packets, yrk, passwrd, iLen2);

			int iLen3 = Parse_GetShort(packets, yrk);
			Parse_GetString(packets, yrk, pcname2, iLen3);

		
			MP_AddByte(byBuff, iOffset, 0x01);
			MP_AddShort(byBuff, iOffset, szAccid.length());
			MP_AddString(byBuff, iOffset, szAccid);
			MP_AddShort(byBuff, iOffset, passwrd.length());
			MP_AddString(byBuff, iOffset, passwrd);
			MP_AddShort(byBuff, iOffset, vala);
			MP_AddShort(byBuff, iOffset, valb);
			MP_AddShort(byBuff, iOffset, valc);
			MP_AddShort(byBuff, iOffset, valx);
			MP_AddShort(byBuff, iOffset, pcname.length());
			MP_AddString(byBuff, iOffset, pcname);
			MP_AddShort(byBuff, iOffset, maczaddr.length());
			MP_AddString(byBuff, iOffset, maczaddr);

		
			std::memset(packets, 0, sizeof(packets));
			std::memcpy(packets, byBuff, iOffset);
			sizes = iOffset;

			// Hooked fonksiyonu çaðýr (gerçek fonksiyonla deðiþtirin)
			hooked();

		
			hex.clear();
			for (size_t i = 0; i < sizes; i++) {
				hex += IntToHex(static_cast<int>(packets[i]), 2);
			}
		
		}
	}

	return 0;
}

// Placeholder fonksiyonlar
void MP_AddByte(BYTE* buffer, int& offset, BYTE value) {
	buffer[offset++] = value;
}

void MP_AddShort(BYTE* buffer, int& offset, short value) {
	std::memcpy(buffer + offset, &value, sizeof(value));
	offset += sizeof(value);
}

void MP_AddString(BYTE* buffer, int& offset, const std::string& str) {
	std::memcpy(buffer + offset, str.c_str(), str.length());
	offset += str.length();
}

short Parse_GetShort(const BYTE* packets, int& offset) {
	short value;
	std::memcpy(&value, packets + offset, sizeof(value));
	offset += sizeof(value);
	return value;
}

void Parse_GetString(const BYTE* packets, int& offset, std::string& str, int len) {
	str.assign(reinterpret_cast<const char*>(packets + offset), len);
	offset += len;
}
std::string GetCpuId() {
	int cpuInfo[4] = { 0 }; // EAX, EBX, ECX, EDX register'larýný tutar

	// CPUID komutunu en temel bilgi türü ile çalýþtýr
	__cpuid(cpuInfo, 0); // Bilgi türü 0 (En temel bilgiler)

	// Verileri birleþtirip string olarak formatlayacaðýz
	std::ostringstream oss;
	oss << std::hex << std::setfill('0') << std::setw(8)
		<< cpuInfo[0] << cpuInfo[1] << cpuInfo[2] << cpuInfo[3]; // EAX, EBX, ECX, EDX deðerlerini birleþtir

	return oss.str();
}
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}


std::string ConvertWStringToString(const std::wstring& wstr) {
	// Dönüþüm için geniþ karakter seti ve dar karakter seti dönüþüm iþlevlerini kullanýr
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
	return str;
}
std::string GetDllDirectory()
{
	char path[MAX_PATH];
	HMODULE hModule = GetModuleHandle("hookedx.dll"); // Mevcut DLL'yi (veya EXE'yi) al
	if (hModule != NULL)
	{
		if (GetModuleFileNameA(hModule, path, MAX_PATH) > 0)
		{
			// Path'i dizine dönüþtür
			std::string fullPath(path);
			size_t pos = fullPath.find_last_of("\\/");
			if (pos != std::string::npos)
			{
				// Path'in sonundaki karaktere kadar al
				std::string directory = fullPath.substr(0, pos + 1);

				// Yol karakterlerini düzelt
				for (char& c : directory)
				{
					if (c == '/')
					{
						c = '\\';
					}
				}

				return directory;
			}
		}
	}
	return "";
}

std::string ReadIniValue(const std::string& section, const std::string& key, const std::string& defaultValue)
{
	char buffer[256];
	std::string iniFilePath = GetDllDirectory() + "settings.ini"; // INI dosyasýnýn yolu

	GetPrivateProfileStringA(
		section.c_str(),    // Bölüm adý (Section)
		key.c_str(),        // Anahtar adý (Key)
		defaultValue.c_str(), // Varsayýlan deðer (Default Value)
		buffer,             // Deðer burada döner
		sizeof(buffer),     // Buffer boyutu
		iniFilePath.c_str() // INI dosyasýnýn yolu
		);

	return std::string(buffer);
}
DWORD KO_FLDB = 0xF58F4C;
DWORD KO_FMBS = 0x51B410;


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		hooksend();
		break;
	case DLL_THREAD_ATTACH:
		// Thread oluþturuldu
		break;
	case DLL_THREAD_DETACH:
		// Thread sonlandý
		break;
	case DLL_PROCESS_DETACH:
		// DLL kaldýrýldý
		break;
	}
	return TRUE;
}