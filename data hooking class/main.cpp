#include "DataHook.h"

#define print(fmt, ...) DbgPrintEx(0, 0, fmt, ##__VA_ARGS__)

void __stdcall Detour()
{
	print("[+] Detour called!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	print("[+] Driver loaded. \n");
	if (DATAHOOK_SUCCESS(DataHook::getFunctionAddress("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtDxgkGetTrackedWorkloadStatistics"))) {
		DataHook::hookFunction(&Detour);
	}
	else
	{
		print("[-] Couldn't find the function. \n");
	}

	return STATUS_SUCCESS;
}