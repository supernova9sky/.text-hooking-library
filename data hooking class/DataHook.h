/*
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
* TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
* OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* 
* THIS LIBRARY WAS CODED BY supernova9sky on github.com
*/

#ifdef _KERNEL_MODE
#pragma once
#if !(defined _M_X64) && !(defined __i386__)
#error DataHook supports only x64 drivers.
#endif

#ifdef __cplusplus
#include <ntdef.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntifs.h>
#include <IntSafe.h>
#include <ntimage.h>
#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "kernel32.lib")

typedef enum DATAHOOK_STATUS
{
	DATAHOOK_ERROR = -1,
	DATAHOOK_COULDNT_FIND_FUNCTION_ERROR = 0,
	DATAHOOK_OK = 1
};
#define DATAHOOK_SUCCESS(status) (((DATAHOOK_STATUS)(status)) == DATAHOOK_OK)

extern "C" NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);

namespace DataHook
{
	typedef enum _SYSTEM_INFORMATION_CLASS
		{
			SystemBasicInformation,
			SystemProcessorInformation,
			SystemPerformanceInformation,
			SystemTimeOfDayInformation,
			SystemPathInformation,
			SystemProcessInformation,
			SystemCallCountInformation,
			SystemDeviceInformation,
			SystemProcessorPerformanceInformation,
			SystemFlagsInformation,
			SystemCallTimeInformation,
			SystemModuleInformation,
			SystemLocksInformation,
			SystemStackTraceInformation,
			SystemPagedPoolInformation,
			SystemNonPagedPoolInformation,
			SystemHandleInformation,
			SystemObjectInformation,
			SystemPageFileInformation,
			SystemVdmInstemulInformation,
			SystemVdmBopInformation,
			SystemFileCacheInformation,
			SystemPoolTagInformation,
			SystemInterruptInformation,
			SystemDpcBehaviorInformation,
			SystemFullMemoryInformation,
			SystemLoadGdiDriverInformation,
			SystemUnloadGdiDriverInformation,
			SystemTimeAdjustmentInformation,
			SystemSummaryMemoryInformation,
			SystemNextEventIdInformation,
			SystemEventIdsInformation,
			SystemCrashDumpInformation,
			SystemExceptionInformation,
			SystemCrashDumpStateInformation,
			SystemKernelDebuggerInformation,
			SystemContextSwitchInformation,
			SystemRegistryQuotaInformation,
			SystemExtendServiceTableInformation,
			SystemPrioritySeperation,
			SystemPlugPlayBusInformation,
			SystemDockInformation,
			SystemProcessorSpeedInformation,
			SystemCurrentTimeZoneInformation,
			SystemLookasideInformation
		} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
		{
			HANDLE Section;
			PVOID MappedBase;
			PVOID ImageBase;
			ULONG ImageSize;
			ULONG Flags;
			USHORT LoadOrderIndex;
			USHORT InitOrderIndex;
			USHORT LoadCount;
			USHORT OffsetToFileName;
			UCHAR  FullPathName[256];
		} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
	typedef struct _RTL_PROCESS_MODULES
		{
			ULONG NumberOfModules;
			RTL_PROCESS_MODULE_INFORMATION Modules[1];
		} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	// !!!!!!!!!!!!!!! DO NOT USE !!!!!!!!!!!!!!!
	PVOID FunctionAddress = nullptr;

	// Hooks a system function.
	// Parameters:
	//--> DetourAddress			[in]  A pointer to a function that is the hook.
	DATAHOOK_STATUS hookFunction(PVOID DetourAddress) {

			//place a r10 jmp hook that returns
			unsigned char shell_code[] = {
				0x49, 0xBA,										// mov r10,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 00000000h << Function pointer is written here!
				0x41, 0xFF, 0xE2,								// jmp r10											
				0xB8, 0x01, 0x00, 0x00, 0xC0,					// making eax STATUS_UNSUCCESSFUL
				0xC3											//			0xC3 ret
			};

			uintptr_t hook_address = reinterpret_cast<uintptr_t>(DetourAddress);
			memcpy(shell_code + 2, &hook_address, sizeof(hook_address));

			PMDL Mdl = IoAllocateMdl(FunctionAddress, sizeof(shell_code), FALSE, FALSE, NULL);
			if (!Mdl)
				return DATAHOOK_ERROR;

			MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
			PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
			MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

			memcpy(Mapping, &shell_code, sizeof(shell_code));
			MmUnmapLockedPages(Mapping, Mdl);
			MmUnlockPages(Mdl);
			IoFreeMdl(Mdl);
			return DATAHOOK_OK;
		}

	// Gets the system function to later hook with the "hookFunction" function.
	// Parameters:
	//--> ModuleNameToGetExport	[in]  A string specifying the module path to get the export from.
	//--> RoutineName			[in]  A string specifying the name of the function to get the address for.
	DATAHOOK_STATUS getFunctionAddress(const char* ModuleNameToGetExport, LPCSTR RoutineName) {
			ULONG bytes = 0;
			NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

			if (!bytes)
				return DATAHOOK_COULDNT_FIND_FUNCTION_ERROR;

			PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

			status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

			if (!NT_SUCCESS(status))
				return DATAHOOK_COULDNT_FIND_FUNCTION_ERROR;

			PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
			PVOID module_base = 0, module_size = 0;

			for (ULONG i = 0; i < modules->NumberOfModules; i++)
			{
				if (strcmp((char*)module[i].FullPathName, ModuleNameToGetExport) == NULL)
				{
					module_base = module[i].ImageBase;
					module_size = (PVOID)module[i].ImageSize;
					break;
				}
			}

			if (modules)
				ExFreePoolWithTag(modules, NULL);

			if (module_base <= NULL)
				return DATAHOOK_COULDNT_FIND_FUNCTION_ERROR;

			if (!module_base)
				return DATAHOOK_COULDNT_FIND_FUNCTION_ERROR;
			PVOID address = RtlFindExportedRoutineByName(module_base, RoutineName);
			if (address > 0) {
				FunctionAddress = address;
				return DATAHOOK_OK;
			} else {
				return DATAHOOK_COULDNT_FIND_FUNCTION_ERROR;
			}
	}
};

#else
#error DataHook supports only c++ drivers.
#endif // __cplusplus
#endif // _KERNEL_MODE