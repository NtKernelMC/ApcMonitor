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
#pragma once
#include <Windows.h>
#include <tuple>
#include <map>
namespace APC
{
	class ApcMonitor
	{
	public:
		typedef void(__stdcall *ApcFilter)(std::tuple<PVOID, PCONTEXT, const char*> *ApcInfo);
		typedef struct
		{
			bool installed;
			ApcFilter callback;
			std::map<PVOID, const char*> ApcList;
		} APC_FILTER, *PAPC_FILTER;
		APC_FILTER flt;
		typedef bool(__cdecl *ptrInstallApcDispatcher)(ApcFilter callback);
		ptrInstallApcDispatcher InstallApcDispatcher;
		typedef bool(__cdecl *ptrDeleteApcDispatcher)();
		ptrDeleteApcDispatcher DeleteApcDispatcher;
		explicit ApcMonitor(HMODULE hModule)
		{
			InstallApcDispatcher = (ptrInstallApcDispatcher)GetProcAddress(hModule, "InstallApcDispatcher");
			DeleteApcDispatcher = (ptrDeleteApcDispatcher)GetProcAddress(hModule, "DeleteApcDispatcher");
		}
	};
}