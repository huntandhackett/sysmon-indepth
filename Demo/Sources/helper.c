/*
 * Copyright (c) 2022 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include "bypass_block_executable.h"
#include <wchar.h>

 // The name of the last function that the thread called
__declspec(thread) PCWSTR LastCall;

// Report progress on a specific operation to the console
BOOLEAN H2ReportStatus(
    _In_ PCWSTR Location,
    _In_ NTSTATUS Status
)
{
    if (NT_SUCCESS(Status))
        wprintf_s(L"%s: Success\r\n", Location);
    else
    {
        // Find ntdll
        PLDR_DATA_TABLE_ENTRY ntdllLdrEntry = CONTAINING_RECORD(
            NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
            LDR_DATA_TABLE_ENTRY,
            InInitializationOrderLinks
        );

        PCWSTR description;
        PMESSAGE_RESOURCE_ENTRY messageEntry;

        // Lookup error description by NTSTATUS
        NTSTATUS status = RtlFindMessage(
            ntdllLdrEntry->DllBase,
            (ULONG)(ULONG_PTR)RT_MESSAGETABLE,
            0,
            (ULONG)Status,
            &messageEntry
        );

        if (NT_SUCCESS(status) && messageEntry->Flags & MESSAGE_RESOURCE_UNICODE)
            description = (PCWSTR)messageEntry->Text;
        else
            description = L"Unknown error";

        wprintf_s(L"%s: 0x%X at %s - %s\r\n", Location, Status, LastCall, description);
    }

    return NT_SUCCESS(Status);
}

// Convert a Win32 filename to native format
NTSTATUS H2DosPathToNtPath(
    _In_ PCWSTR DosFileName,
    _Out_ PUNICODE_STRING NativeFileName
)
{
    LastCall = L"RtlDosLongPathNameToNtPathName_U_WithStatus";
    return RtlDosLongPathNameToNtPathName_U_WithStatus(
        DosFileName,
        NativeFileName,
        NULL,
        NULL
    );
}

// Create or open a file
NTSTATUS H2CreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PUNICODE_STRING FileName,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions
)
{
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK isb;

    InitializeObjectAttributes(&objAttr, FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    LastCall = L"NtCreateFile";
    return NtCreateFile(
        FileHandle,
        DesiredAccess,
        &objAttr,
        &isb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        CreateDisposition,
        CreateOptions,
        NULL,
        0
    );
}

// Write data into the file
NTSTATUS H2WriteFile(
    _In_ HANDLE FileHandle,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK isb;

    LastCall = L"NtWriteFile";
    status = NtWriteFile(
        FileHandle,
        NULL,
        NULL,
        NULL,
        &isb,
        Data,
        DataSize,
        NULL,
        NULL
    );

    if (status == STATUS_PENDING)
        NtWaitForSingleObject(FileHandle, FALSE, NULL);

    return status;
}

// Rename or move a file within volume boundaries
NTSTATUS H2RenameFile(
    _In_ HANDLE FileHandle,
    _In_ PUNICODE_STRING FileName,
    _In_ BOOLEAN ReplaceIfExists
) 
{
    NTSTATUS status;
    ULONG renameInfoSize;
    PFILE_RENAME_INFORMATION renameInfo = NULL;

    renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + FileName->Length;

    status = H2Allocate(renameInfoSize, &renameInfo, HEAP_ZERO_MEMORY);

    if (!NT_SUCCESS(status))
        return status;

    renameInfo->ReplaceIfExists = ReplaceIfExists;
    renameInfo->RootDirectory = NULL;
    renameInfo->FileNameLength = FileName->Length;
    RtlCopyMemory(renameInfo->FileName, FileName->Buffer, FileName->Length);

    IO_STATUS_BLOCK isb;

    LastCall = L"NtSetInformationFile [FileRenameInformation]";
    status = NtSetInformationFile(
        FileHandle,
        &isb,
        renameInfo,
        renameInfoSize,
        FileRenameInformation
    );

    H2Free(renameInfo);
    return status;
}

// Retrieve the current name of a file
NTSTATUS H2QueryNameFile(
    _In_ HANDLE FileHandle,
    _In_ ULONG Flags,
    _Outptr_ PWCHAR *FileName,
    _Out_opt_ ULONG *FileNameChars
)
{
    NTSTATUS status;
    PWCHAR buffer = NULL;
    ULONG bufferChars = RtlGetLongestNtPathLength();
    ULONG required;

    do
    {
        status = H2Allocate(bufferChars * sizeof(WCHAR), &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        LastCall = L"GetFinalPathNameByHandleW";
        required = GetFinalPathNameByHandleW(
            FileHandle,
            buffer,
            bufferChars,
            Flags
        );

        if (required >= bufferChars)
            status = STATUS_BUFFER_TOO_SMALL;
        else if (required == 0)
            status = NTSTATUS_FROM_WIN32(GetLastError());
        else
            status = STATUS_SUCCESS;

        if (!NT_SUCCESS(status))
        {
            H2Free(buffer);
            buffer = NULL;
        }
    } while (status == STATUS_BUFFER_TOO_SMALL);

    if (!NT_SUCCESS(status))
        return status;
    
    *FileName = buffer;

    if (FileNameChars)
        *FileNameChars = bufferChars;

    return status;
}

// Determine and print the file's deletion state and name
VOID H2PrintFileInfo(
    _In_ HANDLE FileHandle
)
{
    NTSTATUS status;
    IO_STATUS_BLOCK isb;
    FILE_STANDARD_INFORMATION standardInfo;

    status = NtQueryInformationFile(
        FileHandle,
        &isb,
        &standardInfo,
        sizeof(standardInfo),
        FileStandardInformation
    );

    wprintf_s(L"Delete pending: ");

    if (NT_SUCCESS(status))
        wprintf_s(standardInfo.DeletePending ? L"Yes\r\n" : L"No\r\n");
    else
        wprintf_s(L"(Error 0x%X)\r\n", status);

    PWSTR fileName;

    status = H2QueryNameFile(
        FileHandle,
        FILE_NAME_OPENED | VOLUME_NAME_DOS,
        &fileName,
        NULL
    );

    wprintf_s(L"Current name: ");

    if (NT_SUCCESS(status))
    {
        wprintf_s(L"%s\r\n", fileName);
        H2Free(fileName);
    }
    else
        wprintf_s(L"(Error 0x%X)\r\n", status);
}

// Query name of a mapped file
NTSTATUS H2QueryNameMappeFile(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING *FileName
)
{
    NTSTATUS status;
    PUNICODE_STRING buffer;
    SIZE_T bufferSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);

    do
    {
        status = H2Allocate(bufferSize, &buffer, 0);

        if (!NT_SUCCESS(status))
            break;

        LastCall = L"NtQueryVirtualMemory [MemoryMappedFilenameInformation]";
        status = NtQueryVirtualMemory(
            Process,
            Address,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (NT_SUCCESS(status))
        {
            *FileName = buffer;
            break;
        }
        else
        {
            H2Free(buffer);
        }

    } while (status == STATUS_BUFFER_OVERFLOW);

    return status;
}

// Map the current executeable file for reading
NTSTATUS H2MapCurrentModule(
    _Out_ PVOID *Data,
    _Out_ ULONG *DataSize
)
{
    NTSTATUS status;
    PUNICODE_STRING currentModuleName;

    // Determine the filename of the current executable
    status = H2QueryNameMappeFile(
        NtCurrentProcess(),
        RtlGetCurrentPeb()->ImageBaseAddress,
        &currentModuleName
    );

    if (!NT_SUCCESS(status))
        return status;

    HANDLE hFile;

    // Open it for reading
    status = H2CreateFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        currentModuleName,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    H2Free(currentModuleName);

    if (!NT_SUCCESS(status))
        return status;

    IO_STATUS_BLOCK isb;
    FILE_STANDARD_INFORMATION info;

    // Determine the size of the file
    LastCall = L"NtQueryInformationFile [FileStandardInformation]";
    status = NtQueryInformationFile(
        hFile,
        &isb,
        &info,
        sizeof(info),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        NtClose(hFile);
        return status;
    }

    HANDLE hSection;
    
    // Create a memory projection object
    LastCall = L"NtCreateSection";
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_COMMIT,
        hFile
    );

    NtClose(hFile);

    if (!NT_SUCCESS(status))
        return status;

    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;
    
    // Map it locally
    LastCall = L"NtMapViewOfSection";
    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READONLY
    );

    NtClose(hSection);

    if (NT_SUCCESS(status))
    {
        *Data = baseAddress;
        *DataSize = info.EndOfFile.LowPart;
    }

    return status;
}
