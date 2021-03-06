#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdio.h>
#include <string>
#include "ApmExport.h"
using namespace std;
void __stdcall AlertableThread()
{
	while (true)
	{
		SleepEx(100, true);
	}
}
void __stdcall ApcFilter(std::tuple<PVOID, PCONTEXT, const char*> *ApcInfo)
{
#ifdef _WIN64
	printf("\nDetected APC for %s routine | Address: 0x%llX\n", get<2>(*ApcInfo), (DWORD64)get<0>(*ApcInfo));
#else
	printf("\nDetected APC for %s routine | Address: 0x%X\n", get<2>(*ApcInfo), (DWORD)get<0>(*ApcInfo));
#endif
}
int main()
{
	APC::ApcMonitor Monitor(LoadLibraryA("ApcMonitor.dll"));
	bool tst = Monitor.InstallApcDispatcher(ApcFilter);
	if (tst) printf("APC monitor installed!\n");
	DWORD tid; CreateThread(0, 0, (LPTHREAD_START_ROUTINE)AlertableThread, 0, 0, &tid);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (hThread)
	{
		char ptr[] = { "Test.dll" };
		QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG)ptr);
		CloseHandle(hThread);
	}
	system("pause");
	return EXIT_SUCCESS;
}