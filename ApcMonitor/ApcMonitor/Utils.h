#pragma once
#include <Windows.h>
#include <map>
#include <string>
#include <Psapi.h>
#include <vector>
//
namespace LgUtils
{
	template<typename First, typename Second>
	auto SearchForDoubleMapMatch = [](const std::map<First, Second> &map, const First first, const Second second) -> bool
	{
		for (auto it : map)
		{
			if (it.first == first && it.second == second) return true;
		}
		return false;
	};
	template<typename First, typename Second>
	bool SearchForSingleMapMatch(const std::map<First, Second> &map, const First key) 
	{
		for (auto it : map)
		{
			if (it.first == key) return true;
		}
		return false;
	}
	std::string SearchForSingleMapMatchAndRet(const std::map<PVOID, const char*> &map, const PVOID key)
	{
		for (auto it : map)
		{
			if (it.first == key) return it.second;
		}
		return "EMPTY";
	}
	auto EnableDebugPrivilege = [](bool fEnable) -> bool
	{
		HANDLE hToken;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
			tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
			AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
			CloseHandle(hToken);
		}
		return true;
	};
	auto strdel = [](char *s, size_t offset, size_t count) -> char*
	{
		size_t len = strlen(s);
		if (offset > len) return s;
		if ((offset + count) > len) count = len - offset;
		strcpy(s + offset, s + offset + count);
		return s;
	};
	auto GetExternalProcName = [](HANDLE hProc) -> std::string
	{
		CHAR szFileName[MAX_PATH + 1];
		K32GetModuleFileNameExA(hProc, NULL, szFileName, MAX_PATH + 1);
		char fname[256]; char *ipt = strrchr(szFileName, '\\');
		memset(fname, 0, sizeof(fname));
		strdel(szFileName, 0, (ipt - szFileName + 1));
		strncpy(fname, szFileName, strlen(szFileName));
		std::string ProcName(fname);
		return ProcName;
	};
	template <typename T>
	auto Contains = [](std::vector<T>& Vec, const T& Element) -> const bool
	{
		if (std::find(Vec.begin(), Vec.end(), Element) != Vec.end()) return true;
		return false;
	};
	auto IsWoW64 = [](HANDLE process) -> BOOL
	{
		SYSTEM_INFO systemInfo = { 0 };
		GetNativeSystemInfo(&systemInfo);
		if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) return TRUE;
		BOOL bIsWow64 = FALSE;
		typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		LPFN_ISWOW64PROCESS fnIsWow64Process;
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(process, &bIsWow64)) return FALSE;
		}
		return bIsWow64;
	};
	auto IsElevated = []() -> bool
	{
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		{
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
			{
				fRet = Elevation.TokenIsElevated;
			}
		}
		if (hToken) CloseHandle(hToken);
		return (bool)fRet;
	};
};