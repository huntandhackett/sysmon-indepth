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

NTSTATUS wmain(int argc, wchar_t* argv[])
{
	NTSTATUS status;
    PVOID data = NULL;
    ULONG dataSize = 0;
    UNICODE_STRING nativeFileName = { 0 };
    HANDLE hFileForTracking = NULL;
    PH2_SYSMON_BYPASS method = NULL;

    wprintf_s(L"A tool for testing Sysmon's FileBlockExecutable event by Hunt & Hackett.\r\n\r\n");

    if (argc <= 2)
    {
        wprintf_s(L"Usage:\r\n");
        wprintf_s(L"  BypassBlockExecutable.exe [Mode] [File name]\r\n\r\n");

        wprintf_s(L"Supported modes:\r\n");
        wprintf_s(L"  0 - non-bypass -- test mode for explicitly triggering detection\r\n");
        wprintf_s(L"  1 - create+open bypass\r\n");
        wprintf_s(L"  2 - supersede bypass\r\n");
        wprintf_s(L"  3 - hardlink bypass\r\n");
        wprintf_s(L"  4 - locking bypass\r\n");
        wprintf_s(L"  5 - mapping bypass\r\n");
        wprintf_s(L"  6 - undelete bypass\r\n");

        wprintf_s(L"The tool copies itself to the provided location using the specified mode.\r\n\r\n");

        return STATUS_INVALID_PARAMETER;
    }

    switch (wcstoul(argv[1], NULL, 0))
    {
        case H2ToolModeNonBypass:
            wprintf_s(L"Mode: non-bypass\r\n");
            method = H2SysmonNonBypassViaCreate;
            break;

        case H2ToolModeBypassCreateOpen:
            wprintf_s(L"Mode: create + open\r\n");
            method = H2SysmonBypassViaCreatePlusOpen;
            break;

        case H2ToolModeBypassSupersede:
            wprintf_s(L"Mode: supersede\r\n");
            method = H2SysmonBypassViaSupersede;
            break;

        case H2ToolModeBypassHardlink:
            wprintf_s(L"Mode: hardlink\r\n");
            method = H2SysmonBypassViaHardlink;
            break;

        case H2ToolModeBypassLock:
            wprintf_s(L"Mode: lock\r\n");
            method = H2SysmonBypassViaLocking;
            break;

        case H2ToolModeBypassMap:
            wprintf_s(L"Mode: map\r\n");
            method = H2SysmonBypassViaMapping;
            break;

        case H2ToolModeBypassUndelete:
            wprintf_s(L"Mode: undelete\r\n");
            method = H2SysmonBypassViaUndeleting;
            break;
    }

    if (!method)
    {
        status = STATUS_INVALID_PARAMETER;
        wprintf_s(L"Unsupported mode specified.\r\n");
        return status;
    }

    /* Prepare the data to write to the target file. 
       We use the current executable for that. */

    status = H2MapCurrentModule(&data, &dataSize);

    if (!NT_SUCCESS(status))
    {
        H2ReportStatus(L"Reading the current executable", status);
        goto CLEANUP;
    }

    /* Convert the specified filename to NT format */

    status = H2DosPathToNtPath(argv[2], &nativeFileName);

    if (!NT_SUCCESS(status))
    {
        H2ReportStatus(L"Converting the provided filename", status);
        goto CLEANUP;
    }

    /* Execute the selected payload */

    status = method(data, dataSize, &nativeFileName, &hFileForTracking);

    if (!NT_SUCCESS(status))
    {
        H2ReportStatus(L"Error", status);
        goto CLEANUP;
    }
    
    /* Print the file state information */

    H2PrintFileInfo(hFileForTracking);

    status = STATUS_SUCCESS;

CLEANUP:
    if (data)
        NtUnmapViewOfSection(NtCurrentProcess(), data);

    if (nativeFileName.Buffer)
        RtlFreeUnicodeString(&nativeFileName);

    if (hFileForTracking)
        NtClose(hFileForTracking);

    return status;
}