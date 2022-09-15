/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#define PHNT_VERSION PHNT_WIN11
#include <phnt_windows.h>
#include <phnt.h>
#include <wchar.h>

typedef enum _H2_TOOL_MODE {
	H2ToolModeNonBypass = 0,
	H2ToolModeBypassCreateOpen = 1,
	H2ToolModeBypassSupersede = 2,
    H2ToolModeBypassHardlink = 3,
    H2ToolModeBypassLock = 4,
    H2ToolModeBypassMap = 5,
    H2ToolModeBypassUndelete = 6,
} H2_TOOL_MODE;

extern __declspec(thread) PCWSTR LastCall;

/* Helper functions */

FORCEINLINE
_Must_inspect_result_
NTSTATUS
H2Allocate(
    _In_ SIZE_T Size,
    _Outptr_ PVOID* Buffer,
    _In_ ULONG Flags
)
{
    PVOID buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, Flags, Size);

    if (buffer)
    {
        *Buffer = buffer;
        return STATUS_SUCCESS;
    }

    LastCall = L"RtlAllocateHeap";
    return STATUS_NO_MEMORY;
}

FORCEINLINE
VOID
H2Free(
    _In_ _Post_ptr_invalid_ PVOID Buffer
)
{
    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Buffer);
}

// Report progress on a specific operation to the console
BOOLEAN H2ReportStatus(
    _In_ PCWSTR Location,
    _In_ NTSTATUS Status
);

// Convert a Win32 filename to native format
NTSTATUS H2DosPathToNtPath(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NativeFileName
);

// Create or open a file
NTSTATUS H2CreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PUNICODE_STRING FileName,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions
);

// Write data into the file
NTSTATUS H2WriteFile(
    _In_ HANDLE FileHandle,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
);

// Rename or move a file within volume boundaries
NTSTATUS H2RenameFile(
    _In_ HANDLE FileHandle,
    _In_ PUNICODE_STRING FileName,
    _In_ BOOLEAN ReplaceIfExists
);

// Retrieve the current name of a file
NTSTATUS H2QueryNameFile(
    _In_ HANDLE FileHandle,
    _In_ ULONG Flags,
    _Outptr_ PWCHAR *FileName,
    _Out_opt_ ULONG *FileNameChars
);

// Determine and print the file's deletion state and name
VOID H2PrintFileInfo(
    _In_ HANDLE FileHandle
);

// Query name of a mapped file
NTSTATUS H2QueryNameMappeFile(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *FileName
);

// Map the current executeable file for reading
NTSTATUS H2MapCurrentModule(
    _Out_ PVOID *Data,
    _Out_ ULONG *DataSize
);

/* Bypasses */

// Shared prototype for bypass routines
typedef NTSTATUS(NTAPI *PH2_SYSMON_BYPASS)(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Non-bypass #0: create, write, close (test mode; Sysmon should delete the file!)
NTSTATUS H2SysmonNonBypassViaCreate(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #1: create, close; open, write, close
NTSTATUS H2SysmonBypassViaCreatePlusOpen(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #2: supersede, write, close
NTSTATUS H2SysmonBypassViaSupersede(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #3: create, write, hardlink, close
NTSTATUS H2SysmonBypassViaHardlink(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #4: create, write, open, lock, close, unlock, close
NTSTATUS H2SysmonBypassViaLocking(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #5: create, write, map, close, unmap
NTSTATUS H2SysmonBypassViaMapping(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);

// Bypass #6: create, write, close, clear pending deletion
NTSTATUS H2SysmonBypassViaUndeleting(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
);
