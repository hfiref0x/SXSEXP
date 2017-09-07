/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        11 Aug 2017
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "wcp.h"

#define ENABLE_VERBOSE_OUTPUT

HANDLE     g_ConOut = NULL;
BOOL       g_ConsoleOutput = FALSE;
BOOL       g_VerboseOutput = FALSE;
WCHAR      g_BE = 0xFEFF;

BOOL       g_bCabinetInitSuccess = FALSE;

HANDLE     hCabinetDll = NULL;

pfnCloseDecompressor pCloseDecompressor = NULL;
pfnCreateDecompressor pCreateDecompressor = NULL;
pfnDecompress pDecompress = NULL;


#define T_PROGRAMTITLE    TEXT("WinSxS files (DCN1/DCM1/DCS1) expand utility v1.2.0")
#define T_UNSUPFORMAT     TEXT("This format is not supported by this tool.")
#define T_ERRORDELTA      TEXT("Error query delta info.")

//
// Help output.
//
#ifdef ENABLE_VERBOSE_OUTPUT
#define T_HELP	L"Expand compressed files from WinSxS folder.\n\n\r\
SXSEXP [/v] Source Destination\n\n\r\
  /v\t\tVerbose output.\n\r\
  Source\tSource file path.\n\r\
  Destination\tDestination file path."
#else
#define T_HELP	L"Expand compressed files from WinSxS folder.\n\n\r\
SXSEXP Source Destination\n\n\r\
  Source\tSource file path.\n\r\
  Destination\tDestination file path."
#endif

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
    )
{
    HANDLE hFile;
    DWORD bytesIO;

    if (
        (lpFileName == NULL) ||
        (Buffer == NULL) ||
        (BufferSize == 0)
        )
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    hFile = CreateFileW(lpFileName,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
    CloseHandle(hFile);

    return (bytesIO == BufferSize);
}

/*
* PrintDataHeader
*
* Purpose:
*
* Output detailed data information to user.
*
*/
VOID PrintDataHeader(
    CFILE_TYPE ft,
    PVOID MappedFile,
    SIZE_T SourceFileSize
    )
{
    DWORD               i, j;
    PDCN_HEADER         pDCN;
    PDCS_HEADER         pDCS;
    DELTA_HEADER_INFO   dhi;
    DELTA_INPUT         Delta;
    SIZE_T              l;
    WCHAR               szBuffer[MAX_PATH * 2];

    if ((MappedFile == NULL) || (SourceFileSize == 0))
        return;

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

    switch (ft) {

        //share same header structure
    case ftDCN:
    case ftDCM:

        if (ft == ftDCN)
            cuiPrintText(g_ConOut,
                TEXT("\n\rDCN_HEADER found, querying delta info.\n\r"), g_ConsoleOutput, TRUE);
        else
            cuiPrintText(g_ConOut,
                TEXT("\n\rDCM_HEADER found, querying delta info.\n\r"), g_ConsoleOutput, TRUE);

        pDCN = (PDCN_HEADER)MappedFile;

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        Delta.lpStart = pDCN->Data;
        Delta.uSize = SourceFileSize - 4;
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            cuiPrintText(g_ConOut, T_ERRORDELTA, g_ConsoleOutput, TRUE);
            break;
        }

        cuiPrintText(g_ConOut, TEXT("\n\rDELTA_HEADER_INFO\n\r"), g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" FileTypeSet\t\t"));
        u64tohex(dhi.FileTypeSet, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" FileType\t\t"));
        u64tohex(dhi.FileType, _strend(szBuffer));
        if (dhi.FileType == DELTA_FILE_TYPE_RAW) {
            _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_RAW)"));
        }
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" Flags\t\t\t"));
        u64tohex(dhi.Flags, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" TargetSize\t\t"));

#ifdef _WIN64
        u64tohex(dhi.TargetSize, _strend(szBuffer));
#else
        ultohex(dhi.TargetSize, _strend(szBuffer));
#endif
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" TargetFileTime\t\t"));
        ultohex(dhi.TargetFileTime.dwLowDateTime, _strend(szBuffer));
        _strcat(szBuffer, TEXT(":"));
        ultohex(dhi.TargetFileTime.dwHighDateTime, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" TargetHashAlgId\t"));
        ultohex(dhi.TargetHashAlgId, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" TargetHash->HashSize\t"));
        ultohex(dhi.TargetHash.HashSize, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        if (dhi.TargetHash.HashSize > DELTA_MAX_HASH_SIZE) {
            cuiPrintText(g_ConOut, TEXT("\n\rHash size exceed DELTA_MAX_HASH_SIZE."), g_ConsoleOutput, TRUE);
        }
        else {
            if (dhi.TargetHash.HashSize > 0) {
                _strcpy(szBuffer, TEXT(" TargetHash->Hash\t"));
                l = _strlen(szBuffer);
                for (i = 0, j = 0; i < dhi.TargetHash.HashSize; i++, j += 2) {
                    wsprintf(&szBuffer[l + j], L"%02x", dhi.TargetHash.HashValue[i]);
                }
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
            }
        }

        break;

    case ftDCS:

        pDCS = (PDCS_HEADER)MappedFile;

        cuiPrintText(g_ConOut, TEXT("\n\rDCS_HEADER found.\n\r"), g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" NumberOfBlocks\t\t"));
        ultostr(pDCS->NumberOfBlocks, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        _strcpy(szBuffer, TEXT(" UncompressedFileSize\t"));
        ultostr(pDCS->UncompressedFileSize, _strend(szBuffer));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
        break;

    default:
        break;
    }
}

/*
* GetTargetFileType
*
* Purpose:
*
* Return container data type.
*
*/
CFILE_TYPE GetTargetFileType(
    VOID *FileBuffer
    )
{
    CFILE_TYPE Result = ftUnknown;

    if (FileBuffer == NULL)
        return Result;

    //check if file is in compressed format 
    if (*((BYTE *)FileBuffer) == 'D' &&
        *((BYTE *)FileBuffer + 1) == 'C' &&
        *((BYTE *)FileBuffer + 3) == 1
        )
    {
        switch (*((BYTE *)FileBuffer + 2)) {

        case 'D':
            Result = ftDCD;
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
            Result = ftUnknown;
            break;

        }
    }
    else {
        //not compressed, check mz header
        if (*((BYTE *)FileBuffer) == 'M' &&
            *((BYTE *)FileBuffer + 1) == 'Z'
            )
        {
            Result = ftMZ;
        }
    }
    return Result;
}

/*
* ProcessFileMZ
*
* Purpose:
*
* Copy Portable Executable to the output buffer, caller must free it with HeapFree.
*
*/
BOOL ProcessFileMZ(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
    )
{
    BOOL bResult = FALSE;
    PVOID Ptr;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    Ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SourceFileSize);
    if (Ptr) {
        *OutputFileBuffer = Ptr;
        *OutputFileBufferSize = SourceFileSize;
        RtlCopyMemory(Ptr, SourceFile, SourceFileSize);
        bResult = TRUE;
    }
    else {
        *OutputFileBuffer = NULL;
        *OutputFileBufferSize = 0;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    return bResult;
}

/*
* ProcessFileDCN
*
* Purpose:
*
* Unpack DCN file to the buffer, caller must free it with HeapFree.
*
*/
BOOL ProcessFileDCN(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
    )
{
    BOOL bResult = FALSE, bCond = FALSE;

    DELTA_HEADER_INFO   dhi;
    DELTA_INPUT         Source, Delta;
    DELTA_OUTPUT        Target;
    PVOID               Data = NULL;
    SIZE_T              DataSize = 0;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    PDCN_HEADER FileHeader = (PDCN_HEADER)SourceFile;

    do {

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        Delta.lpStart = FileHeader->Data;
        Delta.uSize = SourceFileSize - 4; //(size - signature)
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            cuiPrintText(g_ConOut, T_ERRORDELTA, g_ConsoleOutput, TRUE);
            SetLastError(ERROR_BAD_FORMAT);
            break;
        }

        RtlSecureZeroMemory(&Source, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&Target, sizeof(DELTA_OUTPUT));

        bResult = ApplyDeltaB(DELTA_DEFAULT_FLAGS_RAW, Source, Delta, &Target);
        if (bResult) {

            Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Target.uSize);
            if (Data) {
                RtlCopyMemory(Data, Target.lpStart, Target.uSize);
                DataSize = Target.uSize;
            }
            DeltaFree(Target.lpStart);
        }
        else {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }

        *OutputFileBuffer = Data;
        *OutputFileBufferSize = DataSize;

    } while (bCond);

    return bResult;
}

/*
* ProcessFileDCS
*
* Purpose:
*
* Unpack DCS file to the buffer, caller must free it with HeapFree.
*
*/
BOOL ProcessFileDCS(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
    )
{
    BOOL bResult = FALSE, bCond = FALSE;
    COMPRESSOR_HANDLE hDecompressor = 0;
    BYTE *DataBufferPtr = NULL, *DataBuffer = NULL;

    PDCS_HEADER FileHeader = (PDCS_HEADER)SourceFile;
    PDCS_BLOCK Block;

    DWORD NumberOfBlocks = 0, i;
    DWORD BytesRead, BytesDecompressed, NextOffset;

#ifdef ENABLE_VERBOSE_OUTPUT
    WCHAR szBuffer[MAX_PATH];
#endif

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    do {
        SetLastError(0);

        if (!pCreateDecompressor(COMPRESS_RAW | COMPRESS_ALGORITHM_LZMS, NULL, &hDecompressor)) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("\n\rError, while creating decompressor: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        if (FileHeader->UncompressedFileSize == 0) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("\n\rError, UncompressedFileSize is 0"), g_ConsoleOutput, TRUE);
            }
#endif
            break;

        }

        if (FileHeader->NumberOfBlocks == 0) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("\n\rError, NumberOfBlocks is 0"), g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        DataBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileHeader->UncompressedFileSize);
        if (DataBuffer == NULL) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("\n\rError, memory allocation failed: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        DataBufferPtr = DataBuffer;
        NumberOfBlocks = FileHeader->NumberOfBlocks;
        Block = (PDCS_BLOCK)FileHeader->FirstBlock;
        i = 1;

        BytesRead = 0;
        BytesDecompressed = 0;

        while (NumberOfBlocks > 0) {

#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                _strcpy(szBuffer, TEXT("\n\rDCS_BLOCK #"));
                ultostr(i++, _strend(szBuffer));
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

                _strcpy(szBuffer, TEXT(" Block->CompressedBlockSize\t"));
                ultohex(Block->CompressedBlockSize, _strend(szBuffer));
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

                _strcpy(szBuffer, TEXT(" Block->DecompressedBlockSize\t"));
                ultohex(Block->DecompressedBlockSize, _strend(szBuffer));
                cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
            }
#endif

            if (BytesRead + Block->CompressedBlockSize > SourceFileSize) {
#ifdef ENABLE_VERBOSE_OUTPUT
                if (g_VerboseOutput) {
                    cuiPrintText(g_ConOut, TEXT("\n\rError, compressed data size is bigger than file size."), g_ConsoleOutput, TRUE);
                }
#endif
                break;
            }

            if (BytesDecompressed + Block->DecompressedBlockSize > FileHeader->UncompressedFileSize) {
#ifdef ENABLE_VERBOSE_OUTPUT
                if (g_VerboseOutput) {
                    cuiPrintText(g_ConOut, TEXT("\n\rError, uncompressed data size is bigger than known uncompressed file size."), g_ConsoleOutput, TRUE);
                }
#endif
                break;
            }

            BytesDecompressed += Block->DecompressedBlockSize;

            bResult = pDecompress(hDecompressor,
                Block->CompressedData, Block->CompressedBlockSize - 4,
                (BYTE *)DataBufferPtr, Block->DecompressedBlockSize,
                NULL);

            if (!bResult) {
#ifdef ENABLE_VERBOSE_OUTPUT
                if (g_VerboseOutput) {
                    cuiPrintText(g_ConOut, TEXT("\n\rError, decompression failure: "), g_ConsoleOutput, FALSE);
                    cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                }
#endif
                break;
            }

            NumberOfBlocks--;
            if (NumberOfBlocks == 0)
                break;

            DataBufferPtr = (BYTE*)DataBufferPtr + Block->DecompressedBlockSize;
            NextOffset = Block->CompressedBlockSize + 4;
            Block = (DCS_BLOCK*)((BYTE *)Block + NextOffset);
            BytesRead += NextOffset;
        }

        *OutputFileBuffer = DataBuffer;
        *OutputFileBufferSize = FileHeader->UncompressedFileSize;

    } while (bCond);

    if (hDecompressor != NULL)
        pCloseDecompressor(hDecompressor);

    return bResult;
}

/*
* ProcessFileDCM
*
* Purpose:
*
* Unpack DCM file to the buffer, caller must free it with HeapFree.
*
*/
BOOL ProcessFileDCM(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
    )
{
    BOOL                bCond = FALSE, bResult = FALSE;
    PDCM_HEADER         FileHeader = (PDCM_HEADER)SourceFile;

    PVOID               Data = NULL;
    SIZE_T              DataSize = 0;

    DELTA_INPUT         Source, Delta;
    DELTA_OUTPUT        Target;
    DELTA_HEADER_INFO   dhi;

    if ((SourceFile == NULL) ||
        (OutputFileBuffer == NULL) ||
        (OutputFileBufferSize == NULL) ||
        (SourceFileSize == 0)
        )
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }

    do {

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        Delta.lpStart = FileHeader->Data;
        Delta.uSize = SourceFileSize - 4;
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            cuiPrintText(g_ConOut, T_ERRORDELTA, g_ConsoleOutput, TRUE);
            SetLastError(ERROR_BAD_FORMAT);
            break;
        }

        RtlSecureZeroMemory(&Source, sizeof(DELTA_INPUT));

        Source.lpStart = WCP_SrcManifest;
        Source.uSize = sizeof(WCP_SrcManifest);

        RtlSecureZeroMemory(&Target, sizeof(DELTA_OUTPUT));

        bResult = ApplyDeltaB(DELTA_DEFAULT_FLAGS_RAW, Source, Delta, &Target);
        if (bResult) {

            Data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Target.uSize);
            if (Data) {
                RtlCopyMemory(Data, Target.lpStart, Target.uSize);
                DataSize = Target.uSize;
            }
            DeltaFree(Target.lpStart);
        }
        else {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }

        *OutputFileBuffer = Data;
        *OutputFileBufferSize = DataSize;

    } while (bCond);

    return bResult;
}

/*
* ProcessTargetFile
*
* Purpose:
*
* Read input file, depending on data type call dedicated decompressing handler.
*
*/
BOOL ProcessTargetFile(
    LPWSTR lpTargetFileName,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
    )
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE, hFileMapping = NULL;
    PDWORD MappedFile = NULL;
    LARGE_INTEGER FileSize;
    CFILE_TYPE ft;

#ifdef ENABLE_VERBOSE_OUTPUT
    WCHAR szBuffer[MAX_PATH];
#endif

    do {

        if ((lpTargetFileName == NULL) || (OutputFileBuffer == NULL) || (OutputFileBufferSize == NULL))
            break;

        SetLastError(0);

        hFile = CreateFile(lpTargetFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("Error openning source file: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        FileSize.QuadPart = 0;
        if (!GetFileSizeEx(hFile, &FileSize)) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("Error query file size: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

#ifdef ENABLE_VERBOSE_OUTPUT
        if (g_VerboseOutput) {
            RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, TEXT("File size\t\t"));
            ultostr(FileSize.LowPart, _strend(szBuffer));
            _strcat(szBuffer, TEXT(" bytes"));
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
        }
#endif

        if (FileSize.QuadPart < 8) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("File size too small."), g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMapping == NULL) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("File mapping error: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        MappedFile = MapViewOfFile(hFileMapping, PAGE_READWRITE, 0, 0, 0);
        if (MappedFile == NULL) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("Map view of file error: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        ft = GetTargetFileType(MappedFile);
        if (ft == ftUnknown) {
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("File format unknown."), g_ConsoleOutput, TRUE);
            }
#endif
            break;
        }

        switch (ft) {

        case ftMZ:
            bResult = ProcessFileMZ(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("FileType: MZ, file will be copied"), g_ConsoleOutput, TRUE);
            }
#endif
            break;

        case ftDCD:
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("FileType: DCD1 "), g_ConsoleOutput, FALSE);
                cuiPrintText(g_ConOut, T_UNSUPFORMAT, g_ConsoleOutput, TRUE);
            }
#endif
            break;

        case ftDCH:
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("FileType: DCH1 "), g_ConsoleOutput, FALSE);
                cuiPrintText(g_ConOut, T_UNSUPFORMAT, g_ConsoleOutput, TRUE);
            }
#endif
            break;

        case ftDCX:
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("FileType: DCX1 "), g_ConsoleOutput, FALSE);
                cuiPrintText(g_ConOut, T_UNSUPFORMAT, g_ConsoleOutput, TRUE);
            }
#endif
            break;

        case ftDCM:
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                PrintDataHeader(ft, MappedFile, FileSize.LowPart);
            }
#endif
            bResult = ProcessFileDCM(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            break;

        case ftDCN:
#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                PrintDataHeader(ft, MappedFile, FileSize.LowPart);
            }
#endif
            bResult = ProcessFileDCN(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            break;

        case ftDCS:

            if (g_bCabinetInitSuccess == FALSE) {
                cuiPrintText(g_ConOut, TEXT("\n\rRequired Cabinet API are missing, cannot decompress this file."), g_ConsoleOutput, TRUE);
                break;
            }

#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                PrintDataHeader(ft, MappedFile, FileSize.LowPart);
            }
#endif
            bResult = ProcessFileDCS(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            break;

        default:
            bResult = FALSE;
            break;
        }

    } while (bCond);

    if (MappedFile != NULL)
        UnmapViewOfFile(MappedFile);

    if (hFileMapping != NULL)
        CloseHandle(hFileMapping);

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return bResult;
}

/*
* InitCabinetDecompressionAPI
*
* Purpose:
*
* Get Cabinet API decompression function addresses.
* Windows 7 lack of their support.
*
*/
BOOL InitCabinetDecompressionAPI(
    VOID
    )
{
    pDecompress = (pfnDecompress)GetProcAddress(hCabinetDll, "Decompress");
    if (pDecompress == NULL)
        return FALSE;

    pCreateDecompressor = (pfnCreateDecompressor)GetProcAddress(hCabinetDll, "CreateDecompressor");
    if (pCreateDecompressor == NULL)
        return FALSE;

    pCloseDecompressor = (pfnCloseDecompressor)GetProcAddress(hCabinetDll, "CloseDecompressor");
    if (pCloseDecompressor == NULL)
        return FALSE;

    return TRUE;
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    BOOL    cond = FALSE;
    DWORD   dwTmp, paramId = 1;
    UINT    uResult = (UINT)-1;
    LPWSTR  lpCmdLine;
    WCHAR   szBuffer[MAX_PATH * 2];
    WCHAR   szSourceFile[MAX_PATH], szDestinationFile[MAX_PATH];
    PVOID   OutputBuffer = NULL;
    SIZE_T  OutputBufferSize = 0;

    __security_init_cookie();

    do {
        g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (g_ConOut == INVALID_HANDLE_VALUE) {
            break;
        }

        g_ConsoleOutput = TRUE;
        if (!GetConsoleMode(g_ConOut, &dwTmp)) {
            g_ConsoleOutput = FALSE;
        }

        SetConsoleTitle(T_PROGRAMTITLE);
        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &dwTmp, NULL);
        }

        lpCmdLine = GetCommandLine();
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        GetCommandLineParam(lpCmdLine, paramId, szBuffer, MAX_PATH, &dwTmp);
        if (dwTmp > 0) {
            if (_strcmpi(szBuffer, L"/?") == 0) {
                cuiPrintText(g_ConOut, T_HELP, g_ConsoleOutput, TRUE);
                break;
            }

#ifdef ENABLE_VERBOSE_OUTPUT
            if (_strcmpi(szBuffer, L"/v") == 0) {
                g_VerboseOutput = TRUE;
                paramId++;
                GetCommandLineParam(lpCmdLine, paramId, szBuffer, MAX_PATH, &dwTmp);
            }
#endif
            RtlSecureZeroMemory(szSourceFile, sizeof(szSourceFile));
            _strncpy(szSourceFile, MAX_PATH, szBuffer, MAX_PATH);

            if (!PathFileExists(szSourceFile)) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Source File not found"), g_ConsoleOutput, TRUE);
                break;
            }

            dwTmp = 0;
            paramId++;
            RtlSecureZeroMemory(szDestinationFile, sizeof(szDestinationFile));
            GetCommandLineParam(lpCmdLine, paramId, szDestinationFile, MAX_PATH, &dwTmp);
            if (dwTmp == 0) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Destination File not specified"), g_ConsoleOutput, TRUE);
                break;
            }

#ifdef ENABLE_VERBOSE_OUTPUT
            if (g_VerboseOutput) {
                cuiPrintText(g_ConOut, TEXT("Processing target file\t"), g_ConsoleOutput, FALSE);
                cuiPrintText(g_ConOut, szSourceFile, g_ConsoleOutput, TRUE);
            }
#endif

            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            if (GetSystemDirectory(szBuffer, MAX_PATH) == 0) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Could not query Windows directory"), g_ConsoleOutput, TRUE);
                break;
            }
            else {
                _strcat(szBuffer, TEXT("\\cabinet.dll"));
            }
            hCabinetDll = LoadLibrary(szBuffer);
            if (hCabinetDll == NULL) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Error loading Cabinet.dll"), g_ConsoleOutput, TRUE);
                break;
            }

            g_bCabinetInitSuccess = InitCabinetDecompressionAPI();
            if (ProcessTargetFile(szSourceFile, &OutputBuffer, &OutputBufferSize)) {
                uResult = 0;

                if (supWriteBufferToFile(szDestinationFile, OutputBuffer, (DWORD)OutputBufferSize)) {
#ifdef ENABLE_VERBOSE_OUTPUT
                    if (g_VerboseOutput) {
                        cuiPrintText(g_ConOut, TEXT("\n\rOperation Successful"), g_ConsoleOutput, TRUE);
                    }
#endif
                }
                else {
#ifdef ENABLE_VERBOSE_OUTPUT
                    if (g_VerboseOutput) {
                        cuiPrintText(g_ConOut, TEXT("Error, write file: "), g_ConsoleOutput, FALSE);
                        cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
                    }
#endif
                }
                HeapFree(GetProcessHeap(), 0, OutputBuffer);
            }
        }
        else {
            cuiPrintText(g_ConOut, T_HELP, g_ConsoleOutput, TRUE);
        }

    } while (cond);

    if (hCabinetDll != NULL)
        FreeLibrary(hCabinetDll);

    ExitProcess(uResult);
}
