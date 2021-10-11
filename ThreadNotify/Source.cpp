#include "utils.h"



UCHAR ShellCode[] = {
	0x50,
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x87, 0x04, 0x24,
	0xC3
};

void CiThreadNotification(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	PEPROCESS Process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)) && Create)
	{
		if (!Process)
			return;

		auto ProcessName = PsGetProcessImageFileName(Process);
		if (strcmp(ProcessName, "UserMode.exe") == 0)
		{
			DbgPrintEx(
				0, 
				0,
				"[CiThreadNotification] ProcessId: %d | ProcessName: %s", 
				ProcessId, 
				ProcessName);
		}
	}
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	auto mmcssDriver = GetModuleBase(L"mmcss.sys");
	if (!mmcssDriver)
	{
		DbgPrintEx(0, 0, "Failed to find mmcss.sys");
		return STATUS_UNSUCCESSFUL;
	}

	auto fnCiThreadNotification = FindPatternImage(reinterpret_cast<PCHAR>(mmcssDriver), "\x48\x83\xEC\x28\x45", "xxxxx");
	if (!fnCiThreadNotification)
	{
		DbgPrintEx(0, 0, "Failed to find CiThreadNotification()");
		return STATUS_UNSUCCESSFUL;
	}

	*(PVOID*)(ShellCode + 3) = reinterpret_cast<PVOID>(CiThreadNotification);

	if (!WriteToReadOnly(fnCiThreadNotification, ShellCode, sizeof(ShellCode)))
	{
		DbgPrintEx(0, 0, "Failed to Hooking");
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}