/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023 - 2026
*
*  TITLE:       SUP.C
*
*  VERSION:     1.44
*
*  DATE:        07 Mar 2026
*
*  Program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef struct _DELTA_DESC {
    union {
        INT64 Value;
        ALG_ID AlgId;
    };
    LPCWSTR lpMeaning;
} DELTA_DESC, * PDELTA_DESC;

DELTA_DESC DescAlgId[] = {
    { CALG_MD2, L"CALG_MD2" },
    { CALG_MD4, L"CALG_MD4" },
    { CALG_MD5, L"CALG_MD5" },
    { CALG_SHA, L"CALG_SHA" },
    { CALG_SHA1, L"CALG_SHA1" },
    { CALG_MAC, L"CALG_MAC" },
    { CALG_NO_SIGN, L"CALG_NO_SIGN" },
    { CALG_DES, L"CALG_DES" },
    { CALG_3DES, L"CALG_3DES" },
    { CALG_DESX, L"CALG_DESX" },
    { CALG_RC2, L"CALG_RC2" },
    { CALG_RC4, L"CALG_RC4" },
    { CALG_RC5, L"CALG_RC5" },
    { CALG_AES_128, L"CALG_AES_128" },
    { CALG_AES_192, L"CALG_AES_192" },
    { CALG_AES_256, L"CALG_AES_256" },
    { CALG_AES, L"CALG_AES" },
    { CALG_SHA_256, L"CALG_SHA_256" },
    { CALG_SHA_384, L"CALG_SHA_384" },
    { CALG_SHA_512, L"CALG_SHA_512" }
};


DELTA_DESC DescFileType[] = {
    { DELTA_FILE_TYPE_RAW, L"DELTA_FILE_TYPE_RAW" },
    { DELTA_FILE_TYPE_I386, L"DELTA_FILE_TYPE_I386" },
    { DELTA_FILE_TYPE_IA64, L"DELTA_FILE_TYPE_IA64" },
    { DELTA_FILE_TYPE_AMD64, L"DELTA_FILE_TYPE_AMD64" },
    { DELTA_FILE_TYPE_CLI4_I386, L"DELTA_FILE_TYPE_CLI4_I386" },
    { DELTA_FILE_TYPE_CLI4_AMD64, L"DELTA_FILE_TYPE_CLI4_AMD64" },
    { DELTA_FILE_TYPE_CLI4_ARM, L"DELTA_FILE_TYPE_CLI4_ARM" },
    { DELTA_FILE_TYPE_CLI4_ARM64, L"DELTA_FILE_TYPE_CLI4_ARM64" },
    { DELTA_FILE_TYPE_REVERSE_ANY, L"DELTA_FILE_TYPE_REVERSE_ANY" },
    { DELTA_FILE_TYPE_SET_EXECUTABLES_1, L"DELTA_FILE_TYPE_SET_EXECUTABLES_1" },
    { DELTA_FILE_TYPE_SET_EXECUTABLES_2, L"DELTA_FILE_TYPE_SET_EXECUTABLES_2" },
    { DELTA_FILE_TYPE_SET_EXECUTABLES_3, L"DELTA_FILE_TYPE_SET_EXECUTABLES_3" }
};

DELTA_DESC DescDeltaFlags[] = {
    { DELTA_FLAG_NONE, L"DELTA_FLAG_NONE"},
    { DELTA_FLAG_E8, L"DELTA_FLAG_E8"},
    { DELTA_FLAG_MARK, L"DELTA_FLAG_MARK"},
    { DELTA_FLAG_IMPORTS, L"DELTA_FLAG_IMPORTS"},
    { DELTA_FLAG_EXPORTS, L"DELTA_FLAG_EXPORTS"},
    { DELTA_FLAG_RESOURCES, L"DELTA_FLAG_RESOURCES"},
    { DELTA_FLAG_RELOCS, L"DELTA_FLAG_RELOCS"},
    { DELTA_FLAG_I386_SMASHLOCK, L"DELTA_FLAG_I386_SMASHLOCK"},
    { DELTA_FLAG_I386_JMPS, L"DELTA_FLAG_I386_JMPS"},
    { DELTA_FLAG_I386_CALLS, L"DELTA_FLAG_I386_CALLS"},
    { DELTA_FLAG_AMD64_DISASM, L"DELTA_FLAG_AMD64_DISASM"},
    { DELTA_FLAG_AMD64_PDATA, L"DELTA_FLAG_AMD64_PDATA"},
    { DELTA_FLAG_IA64_DISASM, L"DELTA_FLAG_IA64_DISASM"},
    { DELTA_FLAG_IA64_PDATA, L"DELTA_FLAG_IA64_PDATA"},
    { DELTA_FLAG_UNBIND, L"DELTA_FLAG_UNBIND"},
    { DELTA_FLAG_CLI_DISASM, L"DELTA_FLAG_CLI_DISASM"},
    { DELTA_FLAG_CLI_METADATA, L"DELTA_FLAG_CLI_METADATA"},
    { DELTA_FLAG_HEADERS, L"DELTA_FLAG_HEADERS"},
    { DELTA_FLAG_IGNORE_FILE_SIZE_LIMIT, L"DELTA_FLAG_IGNORE_FILE_SIZE_LIMIT"},
    { DELTA_FLAG_IGNORE_OPTIONS_SIZE_LIMIT, L"DELTA_FLAG_IGNORE_OPTIONS_SIZE_LIMIT"},
    { DELTA_FLAG_ARM_DISASM, L"DELTA_FLAG_ARM_DISASM"},
    { DELTA_FLAG_ARM_PDATA, L"DELTA_FLAG_ARM_PDATA"},
    { DELTA_FLAG_CLI4_METADATA, L"DELTA_FLAG_CLI4_METADATA"},
    { DELTA_FLAG_CLI4_DISASM, L"DELTA_FLAG_CLI4_DISASM"},
    { DELTA_FLAG_ARM64_DISASM, L"DELTA_FLAG_ARM64_DISASM"},
    { DELTA_FLAG_ARM64_PDATA, L"DELTA_FLAG_ARM64_PDATA"}
};

DELTA_DESC DescDeltaDefaultFlags[] = {
    {  DELTA_DEFAULT_FLAGS_RAW, L"DELTA_DEFAULT_FLAGS_RAW" },
    {  DELTA_DEFAULT_FLAGS_I386, L"DELTA_DEFAULT_FLAGS_I386" },
    {  DELTA_DEFAULT_FLAGS_IA64, L"DELTA_DEFAULT_FLAGS_IA64" },
    {  DELTA_DEFAULT_FLAGS_AMD64, L"DELTA_DEFAULT_FLAGS_AMD64" },
    {  DELTA_CLI4_FLAGS_I386, L"DELTA_CLI4_FLAGS_I386" },
    {  DELTA_CLI4_FLAGS_AMD64, L"DELTA_CLI4_FLAGS_AMD64" },
    {  DELTA_CLI4_FLAGS_ARM, L"DELTA_CLI4_FLAGS_ARM" },
    {  DELTA_CLI4_FLAGS_ARM64, L"DELTA_CLI4_FLAGS_ARM64" }
};

LPCWSTR lpszMonths[12] = {
      L"Jan",
      L"Feb",
      L"Mar",
      L"Apr",
      L"May",
      L"Jun",
      L"Jul",
      L"Aug",
      L"Sep",
      L"Oct",
      L"Nov",
      L"Dec"
};

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
BOOL supWriteBufferToFile(
    _In_ LPCWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
)
{
    HANDLE hFile;
    DWORD bytesIO = 0;
    BOOL bResult = FALSE;
    LPWSTR lpLongPath = NULL;

    //
    // Return TRUE for zero length files to suppress error output. Not a bug.
    //
    if (BufferSize == 0)
        return TRUE;

    lpLongPath = supConvertToLongPath(lpFileName);
    if (lpLongPath == NULL)
        return FALSE;

    hFile = CreateFile(lpLongPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);

    HeapFree(g_Heap, 0, lpLongPath);

    if (hFile != INVALID_HANDLE_VALUE) {
        bResult = WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL) && (bytesIO == BufferSize);
        CloseHandle(hFile);
    }
    return bResult;
}

__inline WCHAR nibbletoh(BYTE c, BOOLEAN upcase)
{
    if (c < 10)
        return L'0' + c;

    c -= 10;

    if (upcase)
        return L'A' + c;

    return L'a' + c;
}

/*
* supPrintHash
*
* Purpose:
*
* Output hash.
* Returned buffer must be freed with HeapFree when no longer needed.
*
*/
LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex
)
{
    ULONG c;
    SIZE_T sz;
    BYTE x;
    LPWSTR lpText;
    LPWSTR lpOut;

    if (Length == 0 || Buffer == NULL)
        return NULL;

    sz = ((((SIZE_T)Length) * 2) + 1) * sizeof(WCHAR);
    lpText = (LPWSTR)HeapAlloc(g_Heap, 0, sz);
    if (lpText == NULL)
        return NULL;

    lpOut = lpText;

    for (c = 0; c < Length; ++c) {
        x = Buffer[c];
        *lpOut++ = nibbletoh(x >> 4, UpcaseHex);
        *lpOut++ = nibbletoh(x & 0x0F, UpcaseHex);
    }

    *lpOut = 0;

    return lpText;
}

/*
* supPrintDeltaHeaderInfo
*
* Purpose:
*
* Output DELTA_HEADER_INFO fields to user.
*
*/
VOID supPrintDeltaHeaderInfo(
    _In_ PSUP_CONSOLE Console,
    _In_ LPDELTA_HEADER_INFO DeltaHeaderInfo
)
{
    BOOL bFound;
    DWORD i, c;
    INT64 deltaFlags, k;
    LPWSTR lpHash;
    FILETIME localFileTime;
    SYSTEMTIME systemTime;
    WCHAR szBuffer[1024];

    supConsoleWriteLine(Console, TEXT("\r\nDELTA_HEADER_INFO\r\n"));

    //
    // DeltaHeaderInfo->FileTypeSet
    //
    _strcpy(szBuffer, TEXT(" FileTypeSet\t\t0x"));
    u64tohex(DeltaHeaderInfo->FileTypeSet, _strend(szBuffer));
    for (i = 0; i < ARRAYSIZE(DescFileType); i++) {
        if (DescFileType[i].Value == DeltaHeaderInfo->FileTypeSet) {
            _strcat(szBuffer, TEXT("\t"));
            _strcat(szBuffer, DescFileType[i].lpMeaning);
            break;
        }
    }
    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->FileType
    //
    _strcpy(szBuffer, TEXT(" FileType\t\t0x"));
    u64tohex(DeltaHeaderInfo->FileType, _strend(szBuffer));
    for (i = 0; i < ARRAYSIZE(DescFileType); i++) {
        if (DescFileType[i].Value == DeltaHeaderInfo->FileType) {
            _strcat(szBuffer, TEXT("\t"));
            _strcat(szBuffer, DescFileType[i].lpMeaning);
            break;
        }
    }
    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->Flags
    //
    bFound = FALSE;
    _strcpy(szBuffer, TEXT(" Flags\t\t\t0x"));
    u64tohex(DeltaHeaderInfo->Flags, _strend(szBuffer));
    for (i = 0; i < ARRAYSIZE(DescDeltaDefaultFlags); i++) {
        if (DescDeltaDefaultFlags[i].Value == DeltaHeaderInfo->Flags) {
            _strcat(szBuffer, TEXT("\t"));
            _strcat(szBuffer, DescDeltaDefaultFlags[i].lpMeaning);
            bFound = TRUE;
            break;
        }
    }

    c = 0;
    if (bFound == FALSE) {
        deltaFlags = DeltaHeaderInfo->Flags;
        for (i = 0; i < ARRAYSIZE(DescDeltaFlags); i++) {

            if (DescDeltaFlags[i].Value & deltaFlags) {

                if (c == 0)
                    _strcat(szBuffer, TEXT("\t"));
                else
                    _strcat(szBuffer, TEXT(" | "));

                _strcat(szBuffer, DescDeltaFlags[i].lpMeaning);

                deltaFlags &= ~DescDeltaFlags[i].Value;
                c += 1;
            }

        }

        if (deltaFlags) {
            k = 1;
            while (deltaFlags) {
                if (deltaFlags & k) {
                    if (c == 0)
                        _strcat(szBuffer, TEXT("\t"));
                    else
                        _strcat(szBuffer, TEXT(" | "));

                    _strcat(szBuffer, TEXT("0x"));
                    u64tohex(k, _strend(szBuffer));

                    deltaFlags &= ~k;
                }
                k <<= 1;
            }
        }
    }
    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->TargetSize
    //
    _strcpy(szBuffer, TEXT(" TargetSize\t\t0x"));
#ifdef _WIN64
    u64tohex(DeltaHeaderInfo->TargetSize, _strend(szBuffer));
#else
    ultohex(DeltaHeaderInfo->TargetSize, _strend(szBuffer));
#endif
    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->TargetFileTime
    //
    _strcpy(szBuffer, TEXT(" TargetFileTime\t\t0x"));
    ultohex(DeltaHeaderInfo->TargetFileTime.dwLowDateTime, _strend(szBuffer));
    _strcat(szBuffer, TEXT(":"));
    ultohex(DeltaHeaderInfo->TargetFileTime.dwHighDateTime, _strend(szBuffer));

    if (FileTimeToLocalFileTime(&DeltaHeaderInfo->TargetFileTime, &localFileTime) &&
        FileTimeToSystemTime(&localFileTime, &systemTime))
    {
        wsprintf(_strend(szBuffer), L"\t%02hu:%02hu:%02hu, %02hu %ws %04hu",
            systemTime.wHour,
            systemTime.wMinute,
            systemTime.wSecond,
            systemTime.wDay,
            lpszMonths[(systemTime.wMonth ? systemTime.wMonth - 1 : 0)],
            systemTime.wYear);
    }

    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->TargetHashAlgId
    //
    _strcpy(szBuffer, TEXT(" TargetHashAlgId\t0x"));
    ultohex(DeltaHeaderInfo->TargetHashAlgId, _strend(szBuffer));

    for (i = 0; i < ARRAYSIZE(DescAlgId); i++) {
        if (DeltaHeaderInfo->TargetHashAlgId == DescAlgId[i].AlgId) {
            _strcat(szBuffer, TEXT("\t\t"));
            _strcat(szBuffer, DescAlgId[i].lpMeaning);
            break;
        }
    }

    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->HashSize
    //
    _strcpy(szBuffer, TEXT(" TargetHash->HashSize\t0x"));
    ultohex(DeltaHeaderInfo->TargetHash.HashSize, _strend(szBuffer));
    supConsoleWriteLine(Console, szBuffer);

    //
    // DeltaHeaderInfo->TargetHash.Hash
    //
    if (DeltaHeaderInfo->TargetHash.HashSize > DELTA_MAX_HASH_SIZE) {
        supConsoleWriteLine(Console, TEXT("\r\nHash size exceed DELTA_MAX_HASH_SIZE"));
    }
    else {
        if (DeltaHeaderInfo->TargetHash.HashSize > 0) {
            _strcpy(szBuffer, TEXT(" TargetHash->Hash\t0x"));

            lpHash = supPrintHash((PBYTE)&DeltaHeaderInfo->TargetHash.HashValue,
                DeltaHeaderInfo->TargetHash.HashSize,
                TRUE);
            if (lpHash) {
                _strcat(szBuffer, lpHash);
                HeapFree(g_Heap, 0, lpHash);
            }

            supConsoleWriteLine(Console, szBuffer);
        }
    }

}

/*
* supGetFileType
*
* Purpose:
*
* Return container data type.
*
*/
CFILE_TYPE supGetFileType(
    _In_ PVOID FileBuffer,
    _In_ ULONG fileSize
)
{
    CFILE_TYPE Result = ftUnknown;

    if (FileBuffer == NULL || fileSize < 4)
        return ftUnknown;

    //
    // Check if file is in compressed format.
    //
    if (*((BYTE*)FileBuffer) == 'D' &&
        *((BYTE*)FileBuffer + 1) == 'C' &&
        *((BYTE*)FileBuffer + 3) == 1)
    {
        switch (*((BYTE*)FileBuffer + 2)) {

        case 'D':
            Result = ftDCD;
            break;

        case 'H':
            Result = ftDCH;
            break;

        case 'M':
            Result = ftDCM;
            break;

        case 'N':
            Result = ftDCN;
            break;

        case 'S':
            Result = ftDCS;
            break;

        case 'X':
            Result = ftDCX;
            break;

        default:
            break;
        }

    }
    return Result;
}

/*
* supInitializeMsDeltaAPI
*
* Purpose:
*
* Allocate pointers to MsDelta engine routines.
*
*/
BOOL supInitializeMsDeltaAPI(
    _Inout_ PSUP_DELTA_COMPRESSION MsDeltaContext
)
{
    FARPROC pfn;
    HMODULE hModule;

    MsDeltaContext->ApplyDeltaB = NULL;
    MsDeltaContext->DeltaFree = NULL;
    MsDeltaContext->GetDeltaInfoB = NULL;

    hModule = LoadLibrary(TEXT("msdelta.dll"));
    MsDeltaContext->hModule = hModule;

    if (hModule == NULL)
        return FALSE;

    pfn = GetProcAddress(hModule, "ApplyDeltaB");
    if (pfn)
        MsDeltaContext->ApplyDeltaB = (pfnApplyDeltaB)pfn;
    else
        return FALSE;

    pfn = GetProcAddress(hModule, "DeltaFree");
    if (pfn)
        MsDeltaContext->DeltaFree = (pfnDeltaFree)pfn;
    else
        return FALSE;

    pfn = GetProcAddress(hModule, "GetDeltaInfoB");
    if (pfn)
        MsDeltaContext->GetDeltaInfoB = (pfnGetDeltaInfoB)pfn;
    else
        return FALSE;

    return TRUE;
}

/*
* supInitCabinetDecompressionAPI
*
* Purpose:
*
* Get Cabinet API decompression function addresses.
* Windows 7 lack of their support.
*
*/
BOOL supInitCabinetDecompressionAPI(
    _Inout_ PSUP_DECOMPRESSOR Decompressor
)
{
    FARPROC pfn;
    HMODULE hModule;
    WCHAR szBuffer[MAX_PATH + 1];

    Decompressor->Initialized = FALSE;
    Decompressor->CloseDecompressor = NULL;
    Decompressor->CreateDecompressor = NULL;
    Decompressor->Decompress = NULL;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (GetSystemDirectory(szBuffer, MAX_PATH) == 0)
        return FALSE;

    _strcat(szBuffer, TEXT("\\cabinet.dll"));
    hModule = LoadLibrary(szBuffer);
    if (hModule == NULL)
        return FALSE;

    pfn = GetProcAddress(hModule, "Decompress");
    if (pfn)
        Decompressor->Decompress = (pfnDecompress)pfn;
    else
        return FALSE;


    pfn = GetProcAddress(hModule, "CreateDecompressor");
    if (pfn)
        Decompressor->CreateDecompressor = (pfnCreateDecompressor)pfn;
    else
        return FALSE;

    pfn = GetProcAddress(hModule, "CloseDecompressor");
    if (pfn)
        Decompressor->CloseDecompressor = (pfnCloseDecompressor)pfn;
    else
        return FALSE;

    Decompressor->Initialized = TRUE;

    return TRUE;
}

/*
* supConsoleInit
*
* Purpose:
*
* Initialize console context.
*
*/
VOID supConsoleInit(
    _Inout_ PSUP_CONSOLE Console
)
{
    ULONG dummy;
    WCHAR szBE = 0xFEFF;

    Console->ErrorHandle = GetStdHandle(STD_ERROR_HANDLE);
    Console->OutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    Console->Mode = ConsoleModeDefault;

    SetConsoleMode(Console->OutputHandle, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);

    if (!GetConsoleMode(Console->OutputHandle, &dummy)) {
        Console->Mode = ConsoleModeFile;
        WriteFile(Console->OutputHandle, &szBE, sizeof(WCHAR), &dummy, NULL);
    }

}

/*
* supConsoleClear
*
* Purpose:
*
* Clear screen.
*
*/
VOID supConsoleClear(
    _In_ PSUP_CONSOLE Console
)
{
    COORD coordScreen;
    DWORD cCharsWritten;
    DWORD dwConSize;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE handle = Console->OutputHandle;

    if (Console->Mode != ConsoleModeDefault)
        return;

    coordScreen.X = 0;
    coordScreen.Y = 0;

    if (GetConsoleScreenBufferInfo(handle, &csbi)) {

        dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

        if (FillConsoleOutputCharacter(handle, TEXT(' '), dwConSize, coordScreen, &cCharsWritten) &&
            GetConsoleScreenBufferInfo(handle, &csbi) &&
            FillConsoleOutputAttribute(handle, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten))
        {
            SetConsoleCursorPosition(handle, coordScreen);
        }
    }
}

/*
* supConsoleWriteWorker
*
* Purpose:
*
* Output text to the console or file.
*
*/
VOID supConsoleWriteWorker(
    _In_ PSUP_CONSOLE Console,
    _In_ LPCWSTR lpText,
    _In_ BOOL UseReturn,
    _In_ BOOL WriteError
)
{
    SIZE_T size, len;
    DWORD bytesIO;
    LPWSTR buffer;
    HANDLE hOutput;

    if (!lpText)
        return;

    hOutput = WriteError ? Console->ErrorHandle : Console->OutputHandle;

    len = _strlen(lpText);
    size = (6 + len + 2) * sizeof(WCHAR);
    buffer = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (buffer) {

        _strcpy(buffer, lpText);
        if (UseReturn)
            _strcat(buffer, TEXT("\r\n"));

        len = _strlen(buffer);
        if (Console->Mode == ConsoleModeFile) {
            len *= sizeof(WCHAR);
            WriteFile(hOutput, buffer, (DWORD)len, &bytesIO, NULL);
        }
        else {
            WriteConsole(hOutput, buffer, (DWORD)len, &bytesIO, NULL);
        }

        HeapFree(GetProcessHeap(), 0, buffer);
    }
}

/*
* supConsoleWrite
*
* Purpose:
*
* Output LastError translated code to the console or file.
*
*/
VOID supConsoleDisplayWin32Error(
    _In_ PSUP_CONSOLE Console,
    _In_ LPCWSTR Message
)
{
    DWORD dwError = GetLastError();
    ULONG dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
    WCHAR errorBuffer[512];
    WCHAR buffer[1024];

    RtlSecureZeroMemory(buffer, sizeof(buffer));
    RtlSecureZeroMemory(errorBuffer, sizeof(errorBuffer));

    if (Message)
        wsprintf(buffer, TEXT("%ws, GetLastError %lu"), Message, dwError);
    else
        wsprintf(buffer, TEXT("GetLastError %lu"), dwError);

    if (FormatMessage(dwFlags, NULL, dwError, 0, errorBuffer, RTL_NUMBER_OF(errorBuffer), NULL)) {
        _strcat(buffer, TEXT(": "));
        _strcat(buffer, errorBuffer);
    }

    supConsoleWriteErrorLine(Console, buffer);
}

/*
* supMapInputFile
*
* Purpose:
*
* Maps input file into program VA.
*
*/
BOOL supMapInputFile(
    _In_ LPCWSTR FileName,
    _Out_ PULONG FileSize,
    _Out_ PVOID* BaseAddress)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hFile = INVALID_HANDLE_VALUE, hFileMapping = NULL;
    PVOID mappedFile = NULL;
    LARGE_INTEGER fileSize;
    LPWSTR lpLongPath = NULL;

    fileSize.QuadPart = 0;

    do {

        lpLongPath = supConvertToLongPath(FileName);
        if (lpLongPath == NULL) {
            dwError = ERROR_INVALID_PARAMETER;
            break;
        }

        hFile = CreateFile(lpLongPath,
            GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        HeapFree(g_Heap, 0, lpLongPath);
        lpLongPath = NULL;

        if (hFile == INVALID_HANDLE_VALUE) {
            dwError = GetLastError();
            break;
        }

        if (!GetFileSizeEx(hFile, &fileSize)) {
            dwError = GetLastError();
            break;
        }

        if (fileSize.QuadPart < (LONGLONG)sizeof(DCM_HEADER)) {
            dwError = ERROR_NOT_SUPPORTED;
            break;
        }

        if (fileSize.QuadPart > 0x7FFFFFFF) {
            dwError = ERROR_FILE_TOO_LARGE;
            break;
        }

        hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMapping == NULL) {
            dwError = GetLastError();
            break;
        }

        mappedFile = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
        if (mappedFile == NULL) {
            dwError = GetLastError();
        }

    } while (FALSE);

    if (lpLongPath)
        HeapFree(g_Heap, 0, lpLongPath);

    if (hFileMapping)
        CloseHandle(hFileMapping);

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    *BaseAddress = mappedFile;
    *FileSize = (ULONG)fileSize.QuadPart;
    SetLastError(dwError);

    return (mappedFile != NULL);
}

/*
* supxAllocCopyString
*
* Purpose:
*
* Helper routine to allocate memory for the supplied string.
*
*/
LPWSTR supxAllocCopyString(
    _In_ LPCWSTR lpText
)
{
    SIZE_T cchText;
    LPWSTR lpResult;

    if (lpText == NULL)
        return NULL;

    cchText = _strlen(lpText) + 1;
    lpResult = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, cchText * sizeof(WCHAR));
    if (lpResult == NULL)
        return NULL;

    _strcpy(lpResult, lpText);
    return lpResult;
}

/*
* supConvertToLongPath
*
* Purpose:
*
* Converts input path into long path.
*
*/
LPWSTR supConvertToLongPath(
    _In_ LPCWSTR lpPath
)
{
    BOOL isUNC = FALSE;
    BOOL alreadyLong = FALSE;
    SIZE_T pathLen = 0;
    SIZE_T cchRequired = 0;
    LPWSTR lpResult = NULL;

    if (lpPath == NULL || *lpPath == 0)
        return NULL;

    pathLen = _strlen(lpPath);

    //
    // Detect if path is already long or UNC
    //
    if (_strncmp(lpPath, TEXT("\\\\?\\"), 4) == 0)
        alreadyLong = TRUE;

    if (pathLen >= 2 &&
        lpPath[0] == TEXT('\\') &&
        lpPath[1] == TEXT('\\'))
    {
        isUNC = TRUE;
    }

    //
    // If it is already long or less than MAX_PATH return it as is.
    // 
    if (alreadyLong || pathLen < MAX_PATH)
        return supxAllocCopyString(lpPath);

    if (isUNC) {
        cchRequired = pathLen + 7;
        lpResult = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, cchRequired * sizeof(WCHAR));
        if (lpResult == NULL)
            return NULL;

        _strcpy(lpResult, TEXT("\\\\?\\UNC\\"));
        _strcat(lpResult, lpPath + 2);
    }
    else {
        cchRequired = pathLen + 5;
        lpResult = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, cchRequired * sizeof(WCHAR));
        if (lpResult == NULL)
            return NULL;

        _strcpy(lpResult, TEXT("\\\\?\\"));
        _strcat(lpResult, lpPath);
    }

    return lpResult;
}

/*
* supPathFileExists
*
* Purpose:
*
* Checks if the given file/path exists.
*
*/
BOOL supPathFileExists(
    _In_ LPCWSTR lpszPath
)
{
    DWORD attr;
    LPWSTR lpLongPath;

    if (lpszPath == NULL)
        return FALSE;

    lpLongPath = supConvertToLongPath(lpszPath);
    if (lpLongPath == NULL)
        return FALSE;

    attr = GetFileAttributes(lpLongPath);
    HeapFree(g_Heap, 0, lpLongPath);

    return (attr != (DWORD)-1);
}

/*
* supIsDir
*
* Purpose:
*
* Checks if the given file path is a directory.
*
*/
BOOL supIsDir(
    _In_ LPCWSTR lpszPath
)
{
    DWORD attr;
    LPWSTR lpLongPath;

    if (lpszPath == NULL)
        return FALSE;

    lpLongPath = supConvertToLongPath(lpszPath);
    if (lpLongPath == NULL)
        return FALSE;

    attr = GetFileAttributes(lpLongPath);
    HeapFree(g_Heap, 0, lpLongPath);

    return (attr != (DWORD)-1 &&
        (attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
}

/*
* supCreateDirectoryRecursive
*
* Purpose:
*
* Create directories for each path element.
*
*/
BOOL supCreateDirectoryRecursive(
    _In_ LPCWSTR lpDirectory
)
{
    BOOL bResult = FALSE;
    DWORD attr;
    LPWSTR lpPath = NULL;
    LPWSTR lpLongPath = NULL;
    LPWSTR p = NULL;
    SIZE_T cchPath = 0;

    if (lpDirectory == NULL || *lpDirectory == 0)
        return FALSE;

    lpLongPath = supConvertToLongPath(lpDirectory);
    if (lpLongPath == NULL)
        return FALSE;

    attr = GetFileAttributes(lpLongPath);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        bResult = ((attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
        HeapFree(g_Heap, 0, lpLongPath);
        return bResult;
    }

    HeapFree(g_Heap, 0, lpLongPath);
    lpLongPath = NULL;

    cchPath = _strlen(lpDirectory);
    lpPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, (cchPath + 1) * sizeof(WCHAR));
    if (lpPath == NULL)
        return FALSE;

    _strcpy(lpPath, lpDirectory);

    p = lpPath;

    if (((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) &&
        p[1] == L':' && p[2] == L'\\')
    {
        p += 3;
    }
    else if (p[0] == L'\\' && p[1] == L'\\') {
        p += 2;
        while (*p && *p != L'\\')
            p++;
        if (*p == L'\\')
            p++;
        while (*p && *p != L'\\')
            p++;
        if (*p == L'\\')
            p++;
    }

    while (*p) {
        if (*p == L'\\') {
            *p = 0;

            lpLongPath = supConvertToLongPath(lpPath);
            if (lpLongPath == NULL) {
                HeapFree(g_Heap, 0, lpPath);
                return FALSE;
            }

            attr = GetFileAttributes(lpLongPath);
            if (attr == INVALID_FILE_ATTRIBUTES) {
                if (!CreateDirectory(lpLongPath, NULL)) {
                    HeapFree(g_Heap, 0, lpLongPath);
                    HeapFree(g_Heap, 0, lpPath);
                    return FALSE;
                }
            }
            else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                HeapFree(g_Heap, 0, lpLongPath);
                HeapFree(g_Heap, 0, lpPath);
                return FALSE;
            }

            HeapFree(g_Heap, 0, lpLongPath);
            lpLongPath = NULL;

            *p = L'\\';
        }
        p++;
    }

    lpLongPath = supConvertToLongPath(lpPath);
    if (lpLongPath == NULL) {
        HeapFree(g_Heap, 0, lpPath);
        return FALSE;
    }

    attr = GetFileAttributes(lpLongPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        bResult = CreateDirectory(lpLongPath, NULL);
    }
    else {
        bResult = ((attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
    }

    HeapFree(g_Heap, 0, lpLongPath);
    HeapFree(g_Heap, 0, lpPath);

    return bResult;
}
