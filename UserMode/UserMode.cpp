// UserMode.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

void CallHook()
{
	void* FunctionPointer = GetProcAddress(GetModuleHandle(L"win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics");
	auto HookedFunction = static_cast<NTSTATUS(_stdcall*)()>(FunctionPointer);
	HookedFunction();
}

int main()
{
	CallHook();
}
