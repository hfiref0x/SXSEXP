/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.30
*
*  DATE:        31 July 2018
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

HANDLE     g_ConOut = NULL, g_Heap = NULL;
BOOL       g_ConsoleOutput = FALSE;
WCHAR      g_BE = 0xFEFF;

BOOL       g_bCabinetInitSuccess = FALSE;

HANDLE     hCabinetDll = NULL;

pfnCloseDecompressor pCloseDecompressor = NULL;
pfnCreateDecompressor pCreateDecompressor = NULL;
pfnDecompress pDecompress = NULL;


#define T_PROGRAMTITLE    TEXT("WinSxS files (DCN1/DCM1/DCS1/DCD1) expand utility v1.3.0")
#define T_UNSUPFORMAT     TEXT("This format is not supported by this tool.")
#define T_ERRORDELTA      TEXT("Error query delta info.")

//
// Help output.
//
#define T_HELP  L"Expand compressed files from WinSxS folder.\n\n\r\
SXSEXP <Source File> <Destination File>\n\r\
SXSEXP <Source Directory> <Destination Directory>\n\r\
SXSEXP /d <Source File> <Source Delta File> <Destination File>"

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
#define IsDir(lpszPath)          ((GetFileAttributes(lpszPath) & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
#define IsDirWithWFD(data)       ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ==  FILE_ATTRIBUTE_DIRECTORY)
#define ValidDir(data)           (_strcmpi(data.cFileName, TEXT(".")) && _strcmpi(data.cFileName, TEXT("..")))

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
    DWORD bytesIO = 0;

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
* PrintDeltaHeaderInfo
*
* Purpose:
*
* Output DELTA_HEADER_INFO fields to user.
*
*/
VOID PrintDeltaHeaderInfo(
    _In_ LPDELTA_HEADER_INFO pdhi
)
{
    DWORD   i, j;
    SIZE_T  l;
    WCHAR   szBuffer[MAX_PATH * 2];

    cuiPrintText(g_ConOut, TEXT("\n\rDELTA_HEADER_INFO\n\r"), g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" FileTypeSet\t\t"));
    u64tohex(pdhi->FileTypeSet, _strend(szBuffer));
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" FileType\t\t"));
    u64tohex(pdhi->FileType, _strend(szBuffer));

    switch (pdhi->FileType) {

    case DELTA_FILE_TYPE_RAW:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_RAW)"));
        break;

    case DELTA_FILE_TYPE_I386:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_I386)"));
        break;

    case DELTA_FILE_TYPE_IA64:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_IA64)"));
        break;

    case DELTA_FILE_TYPE_AMD64:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_AMD64)"));
        break;

    case DELTA_FILE_TYPE_CLI4_I386:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_CLI4_I386)"));
        break;

    case DELTA_FILE_TYPE_CLI4_AMD64:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_CLI4_AMD64)"));
        break;

    case DELTA_FILE_TYPE_CLI4_ARM:
        _strcat(szBuffer, TEXT(" (DELTA_FILE_TYPE_CLI4_ARM)"));
        break;

    default:
        break;
    }

    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" Flags\t\t\t"));
    u64tohex(pdhi->Flags, _strend(szBuffer));
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" TargetSize\t\t"));

#ifdef _WIN64
    u64tohex(pdhi->TargetSize, _strend(szBuffer));
#else
    ultohex(pdhi->TargetSize, _strend(szBuffer));
#endif
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" TargetFileTime\t\t"));
    ultohex(pdhi->TargetFileTime.dwLowDateTime, _strend(szBuffer));
    _strcat(szBuffer, TEXT(":"));
    ultohex(pdhi->TargetFileTime.dwHighDateTime, _strend(szBuffer));
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" TargetHashAlgId\t"));
    ultohex(pdhi->TargetHashAlgId, _strend(szBuffer));
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    _strcpy(szBuffer, TEXT(" TargetHash->HashSize\t"));
    ultohex(pdhi->TargetHash.HashSize, _strend(szBuffer));
    cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

    if (pdhi->TargetHash.HashSize > DELTA_MAX_HASH_SIZE) {
        cuiPrintText(g_ConOut, TEXT("\n\rHash size exceed DELTA_MAX_HASH_SIZE."), g_ConsoleOutput, TRUE);
    }
    else {
        if (pdhi->TargetHash.HashSize > 0) {
            _strcpy(szBuffer, TEXT(" TargetHash->Hash\t"));
            l = _strlen(szBuffer);
            for (i = 0, j = 0; i < pdhi->TargetHash.HashSize; i++, j += 2) {
                wsprintf(&szBuffer[l + j], L"%02x", pdhi->TargetHash.HashValue[i]);
            }
            cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);
        }
    }

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
    _In_ CFILE_TYPE ft,
    _In_ PVOID MappedFile,
    _In_ SIZE_T SourceFileSize
)
{
    PDCD_HEADER         pDCD;
    PDCN_HEADER         pDCN;
    PDCS_HEADER         pDCS;
    DELTA_HEADER_INFO   dhi;
    DELTA_INPUT         Delta;
    WCHAR               szBuffer[MAX_PATH * 2];

    switch (ft) {

    case ftDCD:
        cuiPrintText(g_ConOut,
            TEXT("\n\rDCD_HEADER found, querying delta info.\n\r"), g_ConsoleOutput, TRUE);

        pDCD = (PDCD_HEADER)MappedFile;

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        Delta.lpStart = pDCD->Data;
        Delta.uSize = SourceFileSize - 12;  //size without header specific fields
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            cuiPrintText(g_ConOut, T_ERRORDELTA, g_ConsoleOutput, TRUE);
            break;
        }

        PrintDeltaHeaderInfo(&dhi);
        break;

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
        Delta.uSize = SourceFileSize - 4; //size without header
        Delta.Editable = FALSE;
        if (!GetDeltaInfoB(Delta, &dhi)) {
            cuiPrintText(g_ConOut, T_ERRORDELTA, g_ConsoleOutput, TRUE);
            break;
        }

        PrintDeltaHeaderInfo(&dhi);
        break;

    case ftDCS:

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

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
    _In_ VOID *FileBuffer
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
_Success_(return == TRUE)
BOOL ProcessFileMZ(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    PVOID Ptr;

    Ptr = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, SourceFileSize);
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
_Success_(return == TRUE)
BOOL ProcessFileDCN(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;

    DELTA_HEADER_INFO   dhi;
    DELTA_INPUT         Source, Delta;
    DELTA_OUTPUT        Target;
    PVOID               Data = NULL;
    SIZE_T              DataSize = 0;

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

            Data = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, Target.uSize);
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
* ProcessFileDCD
*
* Purpose:
*
* Apply DCD file to the source file into the result buffer, caller must free it with HeapFree.
*
*/
_Success_(return == TRUE)
BOOL ProcessFileDCD(
    _In_ PVOID DeltaSourceFile,
    _In_ SIZE_T DeltaSourceFileSize,
    _In_ LPWSTR lpSourceFileName,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER FileSize; 

    SIZE_T DataSize = 0;

    PVOID Data = NULL, SourceFileBuffer = NULL;

    PDCD_HEADER pDCD = (PDCD_HEADER)DeltaSourceFile;

    DWORD bytesIO = 0;

    DELTA_INPUT isrc, idelta;
    DELTA_OUTPUT ioutput;

    do {

        hFile = CreateFile(lpSourceFileName, GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            cuiPrintText(g_ConOut, TEXT("Error openning source file: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        if (!GetFileSizeEx(hFile, &FileSize)) {
            cuiPrintText(g_ConOut, TEXT("Error query source file size: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        if ((FileSize.QuadPart  < 12) || (FileSize.QuadPart  > 2147483648ll)) {
            cuiPrintText(g_ConOut, TEXT("Invalid file size."), g_ConsoleOutput, TRUE);
            break;
        }

        SourceFileBuffer = VirtualAlloc(NULL, FileSize.LowPart,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (SourceFileBuffer == NULL) {
            cuiPrintText(g_ConOut, TEXT("Cannot allocate memory for this operation: "), g_ConsoleOutput, TRUE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        if (!ReadFile(hFile, SourceFileBuffer, FileSize.LowPart, &bytesIO, NULL)) {
            cuiPrintText(g_ConOut, TEXT("Error reading source file: "), g_ConsoleOutput, TRUE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        isrc.Editable = TRUE;
        isrc.lpStart = SourceFileBuffer;
        isrc.uSize = FileSize.LowPart;

        idelta.Editable = FALSE;
        idelta.lpStart = pDCD->Data;
        idelta.uSize = DeltaSourceFileSize - 12; //exclude header fields

        ioutput.lpStart = NULL;
        ioutput.uSize = 0;
        bResult = ApplyDeltaB(DELTA_DEFAULT_FLAGS_RAW, isrc, idelta, &ioutput);
        if (bResult) {

            Data = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, ioutput.uSize);
            if (Data) {
                RtlCopyMemory(Data, ioutput.lpStart, ioutput.uSize);
                DataSize = ioutput.uSize;
            }
            DeltaFree(ioutput.lpStart);
        }
        else {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        }

        *OutputFileBuffer = Data;
        *OutputFileBufferSize = DataSize;

    } while (bCond);

    if (SourceFileBuffer) VirtualFree(SourceFileBuffer, 0, MEM_RELEASE);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

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
_Success_(return == TRUE)
BOOL ProcessFileDCS(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE, bCond = FALSE;
    COMPRESSOR_HANDLE hDecompressor = 0;
    BYTE *DataBufferPtr = NULL, *DataBuffer = NULL;

    PDCS_HEADER FileHeader = (PDCS_HEADER)SourceFile;
    PDCS_BLOCK Block;

    DWORD NumberOfBlocks = 0, i;
    DWORD BytesRead, BytesDecompressed, NextOffset;

    WCHAR szBuffer[MAX_PATH];

    do {
        SetLastError(0);

        if (!pCreateDecompressor(COMPRESS_RAW | COMPRESS_ALGORITHM_LZMS, NULL, &hDecompressor)) {
            cuiPrintText(g_ConOut, TEXT("\n\rError, while creating decompressor: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        if (FileHeader->UncompressedFileSize == 0) {
            cuiPrintText(g_ConOut, TEXT("\n\rError, UncompressedFileSize is 0"), g_ConsoleOutput, TRUE);
            break;

        }

        if (FileHeader->NumberOfBlocks == 0) {
            cuiPrintText(g_ConOut, TEXT("\n\rError, NumberOfBlocks is 0"), g_ConsoleOutput, TRUE);
            break;
        }

        DataBuffer = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, FileHeader->UncompressedFileSize);
        if (DataBuffer == NULL) {
            cuiPrintText(g_ConOut, TEXT("\n\rError, memory allocation failed: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        DataBufferPtr = DataBuffer;
        NumberOfBlocks = FileHeader->NumberOfBlocks;
        Block = (PDCS_BLOCK)FileHeader->FirstBlock;
        i = 1;

        BytesRead = 0;
        BytesDecompressed = 0;

        while (NumberOfBlocks > 0) {

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

            if (BytesRead + Block->CompressedBlockSize > SourceFileSize) {

                cuiPrintText(g_ConOut,
                    TEXT("\n\rError, compressed data size is bigger than file size."),
                    g_ConsoleOutput, TRUE);

                break;
            }

            if (BytesDecompressed + Block->DecompressedBlockSize > FileHeader->UncompressedFileSize) {

                cuiPrintText(g_ConOut,
                    TEXT("\n\rError, uncompressed data size is bigger than known uncompressed file size."),
                    g_ConsoleOutput, TRUE);

                break;
            }

            BytesDecompressed += Block->DecompressedBlockSize;

            bResult = pDecompress(hDecompressor,
                Block->CompressedData, Block->CompressedBlockSize - 4,
                (BYTE *)DataBufferPtr, Block->DecompressedBlockSize,
                NULL);

            if (!bResult) {
                cuiPrintText(g_ConOut, TEXT("\n\rError, decompression failure: "), g_ConsoleOutput, FALSE);
                cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
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
_Success_(return == TRUE)
BOOL ProcessFileDCM(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL                bCond = FALSE, bResult = FALSE;
    PDCM_HEADER         FileHeader = (PDCM_HEADER)SourceFile;

    PVOID               Data = NULL;
    SIZE_T              DataSize = 0;

    DELTA_INPUT         Source, Delta;
    DELTA_OUTPUT        Target;
    DELTA_HEADER_INFO   dhi;

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

            Data = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, Target.uSize);
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
_Success_(return == TRUE)
BOOL ProcessTargetFile(
    _In_ LPWSTR lpTargetFileName,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize,
    _In_opt_ LPWSTR lpDeltaFileName
)
{
    BOOL bCond = FALSE, bResult = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE, hFileMapping = NULL;
    PDWORD MappedFile = NULL;
    LARGE_INTEGER FileSize;
    CFILE_TYPE ft;

    WCHAR szBuffer[MAX_PATH];

    do {

        SetLastError(0);

        hFile = CreateFile(lpTargetFileName,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            0, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            cuiPrintText(g_ConOut, TEXT("Error openning source file: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        FileSize.QuadPart = 0;
        if (!GetFileSizeEx(hFile, &FileSize)) {
            cuiPrintText(g_ConOut, TEXT("Error query file size: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("File size\t\t"));
        ultostr(FileSize.LowPart, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" bytes"));
        cuiPrintText(g_ConOut, szBuffer, g_ConsoleOutput, TRUE);

        if (FileSize.QuadPart < 8) {
            cuiPrintText(g_ConOut, TEXT("File size is too small."), g_ConsoleOutput, TRUE);
            break;
        }

        hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hFileMapping == NULL) {
            cuiPrintText(g_ConOut, TEXT("File mapping error: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        MappedFile = MapViewOfFile(hFileMapping, PAGE_READWRITE, 0, 0, 0);
        if (MappedFile == NULL) {
            cuiPrintText(g_ConOut, TEXT("Map view of file error: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
            break;
        }

        ft = GetTargetFileType(MappedFile);
        if (ft == ftUnknown) {
            cuiPrintText(g_ConOut, TEXT("File format is unknown."), g_ConsoleOutput, TRUE);
            break;
        }

        switch (ft) {

        case ftMZ:
            bResult = ProcessFileMZ(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            cuiPrintText(g_ConOut, TEXT("FileType: MZ, file will be copied"), g_ConsoleOutput, TRUE);
            break;

        case ftDCH:
            cuiPrintText(g_ConOut, TEXT("FileType: DCH1 "), g_ConsoleOutput, FALSE);
            cuiPrintText(g_ConOut, T_UNSUPFORMAT, g_ConsoleOutput, TRUE);
            break;

        case ftDCX:
            cuiPrintText(g_ConOut, TEXT("FileType: DCX1 "), g_ConsoleOutput, FALSE);
            cuiPrintText(g_ConOut, T_UNSUPFORMAT, g_ConsoleOutput, TRUE);
            break;

        case ftDCD:
            if (lpDeltaFileName) {
                PrintDataHeader(ft, MappedFile, FileSize.LowPart);
                bResult = ProcessFileDCD(MappedFile, FileSize.LowPart, lpDeltaFileName, OutputFileBuffer, OutputFileBufferSize);
            }
            break;

        case ftDCM:
            PrintDataHeader(ft, MappedFile, FileSize.LowPart);
            bResult = ProcessFileDCM(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            break;

        case ftDCN:
            PrintDataHeader(ft, MappedFile, FileSize.LowPart);
            bResult = ProcessFileDCN(MappedFile, FileSize.LowPart, OutputFileBuffer, OutputFileBufferSize);
            break;

        case ftDCS:

            if (g_bCabinetInitSuccess == FALSE) {
                cuiPrintText(g_ConOut, TEXT("\n\rRequired Cabinet API are missing, cannot decompress this file."), g_ConsoleOutput, TRUE);
                break;
            }

            PrintDataHeader(ft, MappedFile, FileSize.LowPart);
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
* ProcessTargetFileAndWriteOutput
*
* Purpose:
*
* Expand file.
*
*/
UINT ProcessTargetFileAndWriteOutput(
    _In_ LPWSTR szSourceFile,
    _In_ LPWSTR szDestinationFile
)
{
    PVOID   OutputBuffer = NULL;
    SIZE_T  OutputBufferSize = 0;
    UINT    uResult = (UINT)-1;

    cuiPrintText(g_ConOut, szSourceFile, g_ConsoleOutput, FALSE);
    cuiPrintText(g_ConOut, TEXT(" => "), g_ConsoleOutput, FALSE);
    cuiPrintText(g_ConOut, szDestinationFile, g_ConsoleOutput, TRUE);

    if (ProcessTargetFile(szSourceFile, &OutputBuffer, &OutputBufferSize, NULL)) {
        uResult = 0;

        if (supWriteBufferToFile(szDestinationFile, OutputBuffer, (DWORD)OutputBufferSize)) {
            cuiPrintText(g_ConOut, TEXT("Operation Successful"), g_ConsoleOutput, TRUE);
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Error, write file: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
        }
        if (OutputBuffer) HeapFree(g_Heap, 0, OutputBuffer);
    }
    return uResult;
}

/*
* ProcessTargetDirectory
*
* Purpose:
*
* Recursively process given directory.
*
*/
UINT ProcessTargetDirectory(
    _In_ LPWSTR SourcePath,
    _In_ LPWSTR DestinationPath
)
{
    HANDLE h;
    WIN32_FIND_DATA data;
    UINT  uResult = (UINT)-1;

    LPWSTR lpTemp = NULL, lpSourceChildPath = NULL, lpDestChildPath = NULL;
    SIZE_T memIO, cDataLen, SourcePathLength, DestinationPathLength;

    SourcePathLength = _strlen(SourcePath) * sizeof(WCHAR);
    DestinationPathLength = _strlen(DestinationPath) * sizeof(WCHAR);

    memIO = SourcePathLength + (MAX_PATH * sizeof(WCHAR));
    lpTemp = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpTemp == NULL)
        return uResult;

    _strcpy(lpTemp, SourcePath);
    _strcat(lpTemp, TEXT("*.*"));

    h = FindFirstFile(lpTemp, &data); //lpTemp = c:\windows\*.*
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (IsDirWithWFD(data)) {
                if (ValidDir(data)) {

                    cDataLen = _strlen(data.cFileName) * sizeof(WCHAR);
                    memIO = SourcePathLength + cDataLen + (MAX_PATH * sizeof(WCHAR));
                    lpSourceChildPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);

                    memIO = DestinationPathLength + cDataLen + (MAX_PATH * sizeof(WCHAR));
                    lpDestChildPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);

                    if (lpSourceChildPath && lpDestChildPath) {

                        _strcpy(lpSourceChildPath, SourcePath);
                        _strcat(lpSourceChildPath, data.cFileName);
                        _strcat(lpSourceChildPath, TEXT("\\"));

                        _strcpy(lpDestChildPath, DestinationPath);
                        _strcat(lpDestChildPath, data.cFileName);
                        _strcat(lpDestChildPath, TEXT("\\"));

                        if (!CreateDirectory(lpDestChildPath, NULL) && !PathFileExists(lpDestChildPath)) {
                            cuiPrintText(g_ConOut, TEXT("SXSEXP: unable to create directory "), g_ConsoleOutput, FALSE);
                            cuiPrintText(g_ConOut, lpDestChildPath, g_ConsoleOutput, TRUE);
                            uResult = -1;
                            break;
                        }
                        uResult = ProcessTargetDirectory(lpSourceChildPath, lpDestChildPath);

                        HeapFree(g_Heap, 0, lpDestChildPath);
                        HeapFree(g_Heap, 0, lpSourceChildPath);
                    }
                }
            }
            else {
                cDataLen = _strlen(data.cFileName) * sizeof(WCHAR);
                memIO = SourcePathLength + cDataLen + (MAX_PATH * sizeof(WCHAR));
                lpSourceChildPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);

                memIO = DestinationPathLength + cDataLen + (MAX_PATH * sizeof(WCHAR));
                lpDestChildPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);

                if (lpSourceChildPath && lpDestChildPath) {

                    _strcpy(lpSourceChildPath, SourcePath);
                    _strcat(lpSourceChildPath, data.cFileName);

                    _strcpy(lpDestChildPath, DestinationPath);
                    _strcat(lpDestChildPath, data.cFileName);

                    uResult = ProcessTargetFileAndWriteOutput(lpSourceChildPath, lpDestChildPath);

                    HeapFree(g_Heap, 0, lpDestChildPath);
                    HeapFree(g_Heap, 0, lpSourceChildPath);
                }
            }

        } while (FindNextFile(h, &data));

        FindClose(h);
    }

    HeapFree(g_Heap, 0, lpTemp);
    return uResult;
}

/*
* ProcessTargetPath
*
* Purpose:
*
* Expand files in given directory and subdirectories or just a file.
*
*/
UINT ProcessTargetPath(
    _In_ LPWSTR SourcePath,
    _In_ LPWSTR DestinationPath
)
{
    LPWSTR lpSourceTempPath, lpDestTempPath;
    SIZE_T memIO;
    UINT uResult = (UINT)-1;

    memIO = (MAX_PATH + _strlen(SourcePath)) * sizeof(WCHAR);
    lpSourceTempPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpSourceTempPath == NULL)
        return uResult;

    memIO = (MAX_PATH + _strlen(DestinationPath)) * sizeof(WCHAR);
    lpDestTempPath = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpDestTempPath == NULL) {
        HeapFree(g_Heap, 0, lpSourceTempPath);
        return uResult;
    }

    _strcpy(lpSourceTempPath, SourcePath);
    _strcpy(lpDestTempPath, DestinationPath);

    if (IsDir(lpSourceTempPath) && IsDir(lpDestTempPath)) {

        if (lpSourceTempPath[_strlen(lpSourceTempPath) - 1] != TEXT('\\'))
            _strcat(lpSourceTempPath, TEXT("\\"));

        if (lpDestTempPath[_strlen(lpDestTempPath) - 1] != TEXT('\\'))
            _strcat(lpDestTempPath, TEXT("\\"));

        uResult = ProcessTargetDirectory(lpSourceTempPath, lpDestTempPath);
    }
    else if (!IsDir(lpSourceTempPath)) {
        uResult = ProcessTargetFileAndWriteOutput(lpSourceTempPath, lpDestTempPath);
    }
    else {
        cuiPrintText(g_ConOut, TEXT("SXSEXP: invalid paths specified"), g_ConsoleOutput, TRUE);
        uResult = (UINT)-1;
    }

    HeapFree(g_Heap, 0, lpSourceTempPath);
    HeapFree(g_Heap, 0, lpDestTempPath);

    return uResult;
}

/*
* DCDMode
*
* Purpose:
*
* Special routine to process DCD file type as it requires special approach.
*
*/
VOID DCDMode(
    _In_ LPWSTR lpCmdLine
)
{
    DWORD   dwTmp = 0;

    PVOID   OutputBuffer = NULL;
    SIZE_T  OutputBufferSize = 0;

    WCHAR   szSourcePath[MAX_PATH + 1];
    WCHAR   szSourceDeltaPath[MAX_PATH + 1];
    WCHAR   szDestinationPath[MAX_PATH + 1];

    //
    // Source File.
    //
    RtlSecureZeroMemory(szSourcePath, sizeof(szSourcePath));
    GetCommandLineParam(lpCmdLine, 2, szSourcePath, MAX_PATH, &dwTmp);
    if ((dwTmp == 0) || (!PathFileExists(szSourcePath))) {
        cuiPrintText(g_ConOut, TEXT("SXSEXP: Source Path not found"), g_ConsoleOutput, TRUE);
        return;
    }

    //
    //  Source Delta File.
    //
    RtlSecureZeroMemory(szSourceDeltaPath, sizeof(szSourceDeltaPath));
    GetCommandLineParam(lpCmdLine, 3, szSourceDeltaPath, MAX_PATH, &dwTmp);
    if ((dwTmp == 0) || (!PathFileExists(szSourceDeltaPath))) {
        cuiPrintText(g_ConOut, TEXT("SXSEXP: Source Delta Path not found"), g_ConsoleOutput, TRUE);
        return;
    }

    //
    //  Destination File.
    //
    RtlSecureZeroMemory(szDestinationPath, sizeof(szDestinationPath));
    GetCommandLineParam(lpCmdLine, 4, szDestinationPath, MAX_PATH, &dwTmp);
    if (dwTmp == 0) {
        cuiPrintText(g_ConOut, TEXT("SXSEXP: Destination Path not specified"), g_ConsoleOutput, TRUE);
        return;
    }

    if (ProcessTargetFile(szSourceDeltaPath, &OutputBuffer, &OutputBufferSize, szSourcePath)) {
        if (supWriteBufferToFile(szDestinationPath, OutputBuffer, (DWORD)OutputBufferSize)) {
            cuiPrintText(g_ConOut, TEXT("Operation Successful"), g_ConsoleOutput, TRUE);
        }
        else {
            cuiPrintText(g_ConOut, TEXT("Error, write file: "), g_ConsoleOutput, FALSE);
            cuiPrintTextLastError(g_ConOut, g_ConsoleOutput, TRUE);
        }
        if (OutputBuffer) HeapFree(g_Heap, 0, OutputBuffer);
    }
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
    WCHAR   szSourcePath[MAX_PATH + 1], szDestinationPath[MAX_PATH + 1];

    __security_init_cookie();

    do {

        g_Heap = HeapCreate(HEAP_GROWABLE, 0, 0);
        if (g_Heap == NULL)
            break;

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

            if (_strcmpi(szBuffer, L"/d") == 0) {
                DCDMode(lpCmdLine);
                break;
            }

            RtlSecureZeroMemory(szSourcePath, sizeof(szSourcePath));
            _strncpy(szSourcePath, MAX_PATH, szBuffer, MAX_PATH);

            if (!PathFileExists(szSourcePath)) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Source Path not found"), g_ConsoleOutput, TRUE);
                break;
            }

            dwTmp = 0;
            paramId++;
            RtlSecureZeroMemory(szDestinationPath, sizeof(szDestinationPath));
            GetCommandLineParam(lpCmdLine, paramId, szDestinationPath, MAX_PATH, &dwTmp);
            if (dwTmp == 0) {
                cuiPrintText(g_ConOut, TEXT("SXSEXP: Destination Path not specified"), g_ConsoleOutput, TRUE);
                break;
            }

            cuiPrintText(g_ConOut, TEXT("Processing target path\t"), g_ConsoleOutput, FALSE);
            cuiPrintText(g_ConOut, szSourcePath, g_ConsoleOutput, TRUE);

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

            uResult = ProcessTargetPath(szSourcePath, szDestinationPath);
        }
        else {
            cuiPrintText(g_ConOut, T_HELP, g_ConsoleOutput, TRUE);
        }

    } while (cond);

    if (hCabinetDll != NULL)
        FreeLibrary(hCabinetDll);

    if (g_Heap != NULL)
        HeapDestroy(g_Heap);

    ExitProcess(uResult);
}

