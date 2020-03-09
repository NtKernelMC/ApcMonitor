/*
	Asynchronous Procedure Call Monitor
	Copyrights: NtKernelMC
	Task: APC Monitor for prevention DLL injections
	Creation Date: 19.05.19
	Architecture: x86-x64

	[ENG] Features:
	> Support of x86-x64 architectures for all Windows family system from Vista and higher
	> Filter for forbiddened APC routines
	> Preventing DLL APC Injections
	> APC handler stub performed by MASM
	> Good executable speed
	[RUS] Функционал:
	> Поддержка архитектур х64-х86 для всех операционных систем семейства Windows начиная с Vista и выше
	> Фильтрация для предотвращения нежелательных APC 
	> Защита против инъекций DLL посредством доставки APC
	> Стаб APC обработчика выполнен на MASM
	> Хорошая скорость выполнения
*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tuple>
#include <map>
#include "MinHook.h"
#include "Utils.h"
using namespace std;
#ifdef _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif
typedef void(__stdcall *ApcFilter)(tuple<PVOID, PCONTEXT, const char*> *ApcInfo);
typedef struct
{
	bool installed;
	ApcFilter callback;
	map<PVOID, const char*> ApcList;
} APC_FILTER, *PAPC_FILTER;
APC_FILTER flt;
extern "C" void __stdcall KiApcStub();
extern "C" void __stdcall HandleApc(PVOID ApcRoutine, PVOID Argument, PCONTEXT Context)
{
	auto IsRoutineForbidden = [](PVOID Routine) -> bool
	{
		if (LgUtils::SearchForSingleMapMatch<PVOID, const char*>(flt.ApcList, Routine)) return true;
		return false;
	};
	if (IsRoutineForbidden(Argument))
	{
		char ForbiddenName[45]; memset(ForbiddenName, 0, sizeof(ForbiddenName));
		strcpy(ForbiddenName, LgUtils::SearchForSingleMapMatchAndRet(flt.ApcList, Argument).c_str());
		tuple<PVOID, PCONTEXT, const char*> ApcInfo(Argument, Context, ForbiddenName);
		flt.callback(&ApcInfo);
	}
}
#ifdef _WIN64
extern "C" void __stdcall ApcHandler(PCONTEXT Context)
{
	HandleApc(reinterpret_cast<PVOID>(Context->P4Home), reinterpret_cast<PVOID>(Context->P1Home), Context);
}
#else
extern "C" void __stdcall ApcHandler(PVOID ApcRoutine, PVOID Arg, PCONTEXT Context)
{
	HandleApc(ApcRoutine, Arg, Context);
}
#endif
extern "C" void(__stdcall *OriginalApcDispatcher)(PVOID NormalRoutine, PVOID SysArg1, PVOID SysArg2, CONTEXT Context) = nullptr;
using ApcDispatcherPtr = void(__stdcall *)(PVOID NormalRoutine, PVOID SysArg1, PVOID SysArg2, CONTEXT Context);
extern "C" __declspec(dllexport) bool __cdecl InstallApcDispatcher(ApcFilter callback)
{
	if (flt.installed || callback == nullptr) return false; 
	flt.callback = callback; MH_Initialize();
	OriginalApcDispatcher = (ApcDispatcherPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserApcDispatcher");
	if (OriginalApcDispatcher == nullptr) return false;
	auto MakeForbiddenList = []() -> map<PVOID, const char*>
	{
		map<PVOID, const char*> forbidden;
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), "LoadLibraryA"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"), "LoadLibraryW"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA"), "LoadLibraryExA"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExW"), "LoadLibraryExW"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryA"), "LoadLibraryA"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryW"), "LoadLibraryW"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryExA"), "LoadLibraryExA"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryExW"), "LoadLibraryExW"));
		forbidden.insert(pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll"), "LdrLoadDll"));
		return forbidden;
	}; flt.ApcList = MakeForbiddenList();
	MH_CreateHook(OriginalApcDispatcher, KiApcStub, reinterpret_cast<PVOID*>(&OriginalApcDispatcher));
	MH_EnableHook(MH_ALL_HOOKS); flt.installed ^= true;
	return true;
}
extern "C" __declspec(dllexport) bool __cdecl DeleteApcDispatcher()
{
	if (!flt.installed || OriginalApcDispatcher == nullptr) return false;
	MH_DisableHook(MH_ALL_HOOKS);
	MH_RemoveHook(OriginalApcDispatcher);
	MH_Uninitialize();
	flt.installed ^= true;
	return true;
}
int __stdcall DllMain(HMODULE hModule, DWORD Reason, LPVOID Reserved)
{
    return 1;
}