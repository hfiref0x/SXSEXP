/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.44
*
*  DATE:        07 Mar 2026
*
*  Program entry point.
*
*  Codename: Isonami
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "wcp.h"

HANDLE g_Heap = NULL;

SUP_DECOMPRESSOR gDecompressor;
SUP_DELTA_COMPRESSION gMsDeltaContext;
SUP_CONSOLE gConsole;

#define T_UNSUPFORMAT TEXT("This format is not supported by this tool")
#define T_ERRORDELTA  TEXT("Error query delta info")

//
// Help output.
//
#define T_TITLE TEXT("SXSEXP v1.4.4 from Mar 07 2026, (c) 2016 - 2026 hfiref0x\r\n\
Expand compressed files from WinSxS folder (DCD01, DCN01, DCM01, DCS01 formats).\r\n")

#define T_HELP  TEXT("SXSEXP <Source File> <Destination File>\r\n\
SXSEXP <Source Directory> <Destination Directory>\r\n\
SXSEXP /d <Source File> <Source Delta File> <Destination File>")

/*
* PrintDataHeader
*
* Purpose:
*
* Output detailed data information to user.
*
*/
VOID PrintDataHeader(
    _In_ CFILE_TYPE FileType,
    _In_ PVOID MappedFile,
    _In_ SIZE_T SourceFileSize
)
{
    union {
        PDCD_HEADER pDCD;
        PDCN_HEADER pDCN;
        PDCS_HEADER pDCS;
    } header;

    DELTA_HEADER_INFO dhi;
    DELTA_INPUT inputDelta;
    WCHAR szBuffer[MAX_PATH];

    switch (FileType) {

    case ftDCD:
        supConsoleWriteLine(&gConsole, TEXT("\r\nDCD_HEADER found, querying delta info.\r\n"));

        header.pDCD = (PDCD_HEADER)MappedFile;

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        inputDelta.lpStart = header.pDCD->Data;

        // Size without header specific fields
        inputDelta.uSize = SourceFileSize > (SIZE_T)FIELD_OFFSET(DCD_HEADER, Data) ?
            SourceFileSize - (SIZE_T)FIELD_OFFSET(DCD_HEADER, Data) : 0;
        inputDelta.Editable = FALSE;
        if (inputDelta.uSize == 0 || !gMsDeltaContext.GetDeltaInfoB(inputDelta, &dhi)) {
            supConsoleWriteErrorLine(&gConsole, T_ERRORDELTA);
            break;
        }

        supPrintDeltaHeaderInfo(&gConsole, &dhi);
        break;

        //share same header structure
    case ftDCN:
    case ftDCM:

        if (FileType == ftDCN)
            supConsoleWriteLine(&gConsole, TEXT("\r\nDCN_HEADER found, querying delta information"));
        else
            supConsoleWriteLine(&gConsole, TEXT("\r\nDCM_HEADER found, querying delta information"));

        header.pDCN = (PDCN_HEADER)MappedFile;

        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        inputDelta.lpStart = header.pDCN->Data;

        // Size without header
        inputDelta.uSize = SourceFileSize > (SIZE_T)FIELD_OFFSET(DCN_HEADER, Data) ? 
            SourceFileSize - (SIZE_T)FIELD_OFFSET(DCN_HEADER, Data) : 0;
        inputDelta.Editable = FALSE;
        if (inputDelta.uSize == 0 || !gMsDeltaContext.GetDeltaInfoB(inputDelta, &dhi)) {
            supConsoleWriteErrorLine(&gConsole, T_ERRORDELTA);
            break;
        }

        supPrintDeltaHeaderInfo(&gConsole, &dhi);
        break;

    case ftDCS:

        header.pDCS = (PDCS_HEADER)MappedFile;

        supConsoleWriteLine(&gConsole, TEXT("\r\nDCS_HEADER found.\r\n"));

        _strcpy(szBuffer, TEXT(" NumberOfBlocks\t\t"));
        ultostr(header.pDCS->NumberOfBlocks, _strend(szBuffer));
        supConsoleWriteLine(&gConsole, szBuffer);

        _strcpy(szBuffer, TEXT(" UncompressedFileSize\t"));
        ultostr(header.pDCS->UncompressedFileSize, _strend(szBuffer));
        supConsoleWriteLine(&gConsole, szBuffer);
        break;

    }
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
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID* OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    DWORD dwLastError = ERROR_SUCCESS;
    DELTA_HEADER_INFO deltaHeaderInfo;
    DELTA_INPUT sourceDelta, inputDelta;
    DELTA_OUTPUT targetOutput;
    PVOID pvData = NULL;
    SIZE_T cbData = 0;

    RtlSecureZeroMemory(&deltaHeaderInfo, sizeof(DELTA_HEADER_INFO));
    inputDelta.Editable = FALSE;
    inputDelta.lpStart = ((PDCN_HEADER)SourceFile)->Data;
    inputDelta.uSize = SourceFileSize > (SIZE_T)FIELD_OFFSET(DCN_HEADER, Data) ? 
        SourceFileSize - (SIZE_T)FIELD_OFFSET(DCN_HEADER, Data) : 0;
    if (inputDelta.uSize && gMsDeltaContext.GetDeltaInfoB(inputDelta, &deltaHeaderInfo)) {

        RtlSecureZeroMemory(&sourceDelta, sizeof(DELTA_INPUT));
        RtlSecureZeroMemory(&targetOutput, sizeof(DELTA_OUTPUT));

        bResult = gMsDeltaContext.ApplyDeltaB(DELTA_FLAG_NONE, sourceDelta, inputDelta, &targetOutput);
        if (bResult) {

            pvData = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, targetOutput.uSize);
            if (pvData) {
                RtlCopyMemory(pvData, targetOutput.lpStart, targetOutput.uSize);
                cbData = targetOutput.uSize;
            }
            else {
                dwLastError = GetLastError();
            }
            gMsDeltaContext.DeltaFree(targetOutput.lpStart);
        }
        else {
            dwLastError = GetLastError();
        }

    }
    else {
        dwLastError = GetLastError();
    }

    *OutputFileBuffer = pvData;
    *OutputFileBufferSize = cbData;
    SetLastError(dwLastError);

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
BOOL ProcessFileDCD(
    _In_ PVOID DeltaSourceFile,
    _In_ SIZE_T DeltaSourceFileSize,
    _In_ LPCWSTR lpSourceFileName,
    _Out_ PVOID* OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    DWORD bytesIO = 0, dwLastError = ERROR_SUCCESS;

    SIZE_T cbData = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PVOID pvData = NULL, sourceFileBuffer = NULL;
    LARGE_INTEGER FileSize;
    DELTA_INPUT isrc, idelta;
    DELTA_OUTPUT ioutput;

    FileSize.QuadPart = 0;
    *OutputFileBuffer = NULL;
    *OutputFileBufferSize = 0;

    do {

        hFile = CreateFile(lpSourceFileName,
            GENERIC_READ | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("Error opening source file"));
            break;
        }

        if (!GetFileSizeEx(hFile, &FileSize)) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("Error query source file size"));
            break;
        }

        if ((FileSize.QuadPart < FIELD_OFFSET(DCD_HEADER, Data)) || (FileSize.QuadPart > 0x80000000)) {
            dwLastError = ERROR_INVALID_DATA;
            supConsoleWriteErrorLine(&gConsole, TEXT("Invalid file size"));
            break;
        }

        sourceFileBuffer = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, FileSize.LowPart);
        if (sourceFileBuffer == NULL) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("Cannot allocate memory for this operation"));
            break;
        }

        if (!ReadFile(hFile, sourceFileBuffer, FileSize.LowPart, &bytesIO, NULL) || bytesIO != FileSize.LowPart) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("Error reading source file"));
            break;
        }

        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        isrc.Editable = TRUE;
        isrc.lpStart = sourceFileBuffer;
        isrc.uSize = FileSize.LowPart;

        idelta.Editable = FALSE;
        idelta.lpStart = ((PDCD_HEADER)DeltaSourceFile)->Data;

        // Exclude header fields
        idelta.uSize = DeltaSourceFileSize > (SIZE_T)FIELD_OFFSET(DCD_HEADER, Data) ? 
            DeltaSourceFileSize - (SIZE_T)FIELD_OFFSET(DCD_HEADER, Data) : 0;
        if (idelta.uSize == 0) {
            dwLastError = ERROR_INVALID_DATA;
            break;
        }

        ioutput.lpStart = NULL;
        ioutput.uSize = 0;
        bResult = gMsDeltaContext.ApplyDeltaB(DELTA_FLAG_NONE, isrc, idelta, &ioutput);
        if (bResult) {

            pvData = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, ioutput.uSize);
            if (pvData) {
                RtlCopyMemory(pvData, ioutput.lpStart, ioutput.uSize);
                cbData = ioutput.uSize;
            }
            else {
                dwLastError = GetLastError();
            }
            gMsDeltaContext.DeltaFree(ioutput.lpStart);
        }
        else {
            dwLastError = GetLastError();
        }

    } while (FALSE);

    if (sourceFileBuffer)
        HeapFree(g_Heap, 0, sourceFileBuffer);

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    *OutputFileBuffer = pvData;
    *OutputFileBufferSize = cbData;

    SetLastError(dwLastError);

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
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID* OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    DWORD numberOfBlocks = 0, i = 1, dwLastError = ERROR_SUCCESS;
    DWORD nextOffset = 0;
    SIZE_T bytesRead = 0, bytesDecompressed = 0, remainingSize = 0;
    COMPRESSOR_HANDLE hDecompressor = 0;
    BYTE* dataBufferPtr = NULL;
    BYTE* dataBuffer = NULL;
    PDCS_HEADER fileHeader = (PDCS_HEADER)SourceFile;
    PDCS_BLOCK dcsBlock = NULL;
    WCHAR szBuffer[MAX_PATH];

    *OutputFileBuffer = NULL;
    *OutputFileBufferSize = 0;

    if (gDecompressor.Initialized == FALSE) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return FALSE;
    }

    do {
        if (SourceFileSize < (SIZE_T)FIELD_OFFSET(DCS_HEADER, FirstBlock)) {
            dwLastError = ERROR_INVALID_DATA;
            supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, invalid DCS header"));
            break;
        }

        if (fileHeader->UncompressedFileSize == 0 || fileHeader->NumberOfBlocks == 0) {
            dwLastError = ERROR_INVALID_USER_BUFFER;
            supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, header fields are zero"));
            break;
        }

        if (!gDecompressor.CreateDecompressor(COMPRESS_RAW | COMPRESS_ALGORITHM_LZMS, NULL, &hDecompressor)) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("\r\nError, while creating decompressor"));
            break;
        }

        dataBuffer = (BYTE*)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, fileHeader->UncompressedFileSize);
        if (dataBuffer == NULL) {
            dwLastError = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("\r\nError, memory allocation failed"));
            break;
        }

        dataBufferPtr = dataBuffer;
        numberOfBlocks = fileHeader->NumberOfBlocks;
        dcsBlock = (PDCS_BLOCK)fileHeader->FirstBlock;
        bytesRead = FIELD_OFFSET(DCS_HEADER, FirstBlock);

        while (numberOfBlocks > 0) {

            if ((BYTE*)dcsBlock < (BYTE*)SourceFile || (BYTE*)dcsBlock >= ((BYTE*)SourceFile + SourceFileSize)) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("Corrupt DCS block pointer"));
                bResult = FALSE;
                break;
            }

            remainingSize = (SIZE_T)(((BYTE*)SourceFile + SourceFileSize) - (BYTE*)dcsBlock);

            if (remainingSize < sizeof(DWORD) * 2) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("Corrupt DCS block header"));
                bResult = FALSE;
                break;
            }

            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            _strcpy(szBuffer, TEXT("\r\nDCS_BLOCK #"));
            ultostr(i++, _strend(szBuffer));
            supConsoleWriteLine(&gConsole, szBuffer);

            _strcpy(szBuffer, TEXT(" Block->CompressedBlockSize\t0x"));
            ultohex(dcsBlock->Size, _strend(szBuffer));
            supConsoleWriteLine(&gConsole, szBuffer);

            _strcpy(szBuffer, TEXT(" Block->DecompressedBlockSize\t0x"));
            ultohex(dcsBlock->DecompressedBlockSize, _strend(szBuffer));
            supConsoleWriteLine(&gConsole, szBuffer);

            if (dcsBlock->Size < 4) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, invalid compressed block size"));
                bResult = FALSE;
                break;
            }

            if (bytesRead + dcsBlock->Size > SourceFileSize) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, compressed data size is bigger than file size"));
                bResult = FALSE;
                break;
            }

            if ((SIZE_T)bytesDecompressed + dcsBlock->DecompressedBlockSize > fileHeader->UncompressedFileSize) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, uncompressed data size is bigger than known uncompressed file size"));
                bResult = FALSE;
                break;
            }

            if ((SIZE_T)dcsBlock->Size + 4 > remainingSize) {
                dwLastError = ERROR_INVALID_DATA;
                supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, block overruns file"));
                bResult = FALSE;
                break;
            }

            bResult = gDecompressor.Decompress(hDecompressor,
                dcsBlock->Data,
                (SIZE_T)(dcsBlock->Size - 4),
                (BYTE*)dataBufferPtr,
                dcsBlock->DecompressedBlockSize,
                NULL);

            if (!bResult) {
                dwLastError = GetLastError();
                supConsoleDisplayWin32Error(&gConsole, TEXT("Error, decompression failure"));
                break;
            }

            supConsoleWriteLine(&gConsole, TEXT(" Block has been decompressed successfully"));

            dataBufferPtr = (BYTE*)dataBufferPtr + dcsBlock->DecompressedBlockSize;
            bytesDecompressed += dcsBlock->DecompressedBlockSize;
            nextOffset = dcsBlock->Size + 4;

            if (--numberOfBlocks > 0) {
                dcsBlock = (PDCS_BLOCK)(((BYTE*)dcsBlock) + nextOffset);
                bytesRead += nextOffset;
            }
        }

        if (bResult && bytesDecompressed != fileHeader->UncompressedFileSize) {
            dwLastError = ERROR_INVALID_DATA;
            supConsoleWriteErrorLine(&gConsole, TEXT("\r\nError, total decompressed size mismatch"));
            bResult = FALSE;
        }

        if (bResult) {
            *OutputFileBuffer = dataBuffer;
            *OutputFileBufferSize = fileHeader->UncompressedFileSize;
        }
        else {
            HeapFree(g_Heap, 0, dataBuffer);
            *OutputFileBuffer = NULL;
            *OutputFileBufferSize = 0;
        }

    } while (FALSE);

    if (hDecompressor != NULL)
        gDecompressor.CloseDecompressor(hDecompressor);

    SetLastError(dwLastError);

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
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID* OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
)
{
    BOOL bResult = FALSE;
    DWORD dwLastError = ERROR_SUCCESS;
    PVOID pvData = NULL;
    SIZE_T cbData = 0;
    DELTA_INPUT sourceDelta, inputDelta;
    DELTA_OUTPUT targetDelta;
    DELTA_HEADER_INFO dhi;

    do {
        RtlSecureZeroMemory(&dhi, sizeof(DELTA_HEADER_INFO));
        inputDelta.Editable = FALSE;
        inputDelta.lpStart = ((PDCM_HEADER)SourceFile)->Data;
        inputDelta.uSize = SourceFileSize > (SIZE_T)FIELD_OFFSET(DCM_HEADER, Data) ? 
            SourceFileSize - (SIZE_T)FIELD_OFFSET(DCM_HEADER, Data) : 0;
        if (inputDelta.uSize == 0 || !gMsDeltaContext.GetDeltaInfoB(inputDelta, &dhi)) {
            dwLastError = GetLastError();
            supConsoleWriteErrorLine(&gConsole, T_ERRORDELTA);
            break;
        }

        RtlSecureZeroMemory(&sourceDelta, sizeof(DELTA_INPUT));

        sourceDelta.lpStart = WCP_SrcManifest;
        sourceDelta.uSize = sizeof(WCP_SrcManifest);

        RtlSecureZeroMemory(&targetDelta, sizeof(DELTA_OUTPUT));

        bResult = gMsDeltaContext.ApplyDeltaB(DELTA_FLAG_NONE, sourceDelta, inputDelta, &targetDelta);
        if (bResult) {

            pvData = HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, targetDelta.uSize);
            if (pvData) {
                RtlCopyMemory(pvData, targetDelta.lpStart, targetDelta.uSize);
                cbData = targetDelta.uSize;
            }
            else {
                dwLastError = GetLastError();
            }

            gMsDeltaContext.DeltaFree(targetDelta.lpStart);
        }
        else {
            dwLastError = GetLastError();
        }

    } while (FALSE);

    *OutputFileBuffer = pvData;
    *OutputFileBufferSize = cbData;

    SetLastError(dwLastError);

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
    _In_ LPCWSTR lpTargetFileName,
    _Inout_ PVOID* pvOutputBuffer,
    _Out_ PSIZE_T pbOutputBuffer,
    _In_opt_ LPCWSTR lpDeltaFileName
)
{
    BOOL bResult = FALSE;
    DWORD dwLastError = ERROR_SUCCESS;
    PVOID mappedFile = NULL;
    ULONG fileSize = 0;
    CFILE_TYPE fileType;

    WCHAR szBuffer[MAX_PATH];

    *pvOutputBuffer = NULL;
    *pbOutputBuffer = 0;

    do {
        if (!supMapInputFile(lpTargetFileName, &fileSize, &mappedFile) || mappedFile == NULL) {
            dwLastError = GetLastError(); //error is reported elsewhere
            break;
        }

        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("File size\t\t"));
        ultostr(fileSize, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" bytes"));
        supConsoleWriteLine(&gConsole, szBuffer);

        fileType = supGetFileType(mappedFile, fileSize);
        if (fileType == ftUnknown) {
            dwLastError = ERROR_NOT_SUPPORTED; //error is reported elsewhere
            break;
        }

        switch (fileType) {

        case ftDCH:
            dwLastError = ERROR_INVALID_DATA;
            supConsoleWriteError(&gConsole, TEXT("FileType: DCH1 "));
            supConsoleWriteErrorLine(&gConsole, T_UNSUPFORMAT);
            break;

        case ftDCX:
            dwLastError = ERROR_INVALID_DATA;
            supConsoleWriteError(&gConsole, TEXT("FileType: DCX1 (please report it to program authors) "));
            supConsoleWriteErrorLine(&gConsole, T_UNSUPFORMAT);
            break;

        case ftDCD:
            if (lpDeltaFileName) {
                PrintDataHeader(fileType, mappedFile, fileSize);
                bResult = ProcessFileDCD(mappedFile, fileSize, lpDeltaFileName, pvOutputBuffer, pbOutputBuffer);
                if (!bResult)
                    dwLastError = GetLastError();
            }
            else {
                supConsoleWriteErrorLine(&gConsole, TEXT("Delta filename not specified, use /d to unpack DCD01 files, this cannot be done in directory scan mode"));
                dwLastError = ERROR_INVALID_PARAMETER;
            }
            break;

        case ftDCM:
            PrintDataHeader(fileType, mappedFile, fileSize);
            bResult = ProcessFileDCM(mappedFile, fileSize, pvOutputBuffer, pbOutputBuffer);
            if (!bResult)
                dwLastError = GetLastError();
            break;

        case ftDCN:
            PrintDataHeader(fileType, mappedFile, fileSize);
            bResult = ProcessFileDCN(mappedFile, fileSize, pvOutputBuffer, pbOutputBuffer);
            if (!bResult)
                dwLastError = GetLastError();
            break;

        case ftDCS:

            if (gDecompressor.Initialized == FALSE) {
                dwLastError = ERROR_INTERNAL_ERROR;
                supConsoleWriteErrorLine(&gConsole, TEXT("\r\nRequired Cabinet API are missing, cannot decompress this file."));
                break;
            }

            PrintDataHeader(fileType, mappedFile, fileSize);
            bResult = ProcessFileDCS(mappedFile, fileSize, pvOutputBuffer, pbOutputBuffer);
            if (!bResult)
                dwLastError = GetLastError();
            break;
        }

    } while (FALSE);

    if (mappedFile != NULL)
        UnmapViewOfFile(mappedFile);

    SetLastError(dwLastError);

    return bResult;
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
    _In_ LPCWSTR lpszSourceFile,
    _In_ LPCWSTR lpszDestinationFile
)
{
    PVOID outputBuffer = NULL;
    SIZE_T outputBufferSize = 0;
    UINT uResult = ERROR_SUCCESS;

    supConsoleWrite(&gConsole, TEXT("\r\n"));
    supConsoleWrite(&gConsole, lpszSourceFile);
    supConsoleWrite(&gConsole, TEXT(" => "));
    supConsoleWriteLine(&gConsole, lpszDestinationFile);

    if (ProcessTargetFile(lpszSourceFile, &outputBuffer, &outputBufferSize, NULL)) {
        if (supWriteBufferToFile(lpszDestinationFile, outputBuffer, (DWORD)outputBufferSize)) {
            supConsoleWriteLine(&gConsole, TEXT("\nOperation Successful"));
        }
        else {
            uResult = GetLastError();
            supConsoleDisplayWin32Error(&gConsole, TEXT("Error write to file"));
        }
        if (outputBuffer)
            HeapFree(g_Heap, 0, outputBuffer);
    }
    else if (GetLastError() == ERROR_NOT_SUPPORTED) {
        supConsoleWriteLine(&gConsole, TEXT("File format is unknown, skipping"));
    }
    else {
        uResult = GetLastError();
        supConsoleDisplayWin32Error(&gConsole, TEXT("Error mapping input file"));
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
    _In_ LPCWSTR SourcePath,
    _In_ LPCWSTR DestinationPath
)
{
    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA data;
    UINT uResult = ERROR_SUCCESS;
    DWORD attr;
    LPWSTR lpTemp = NULL, lpSourceChildPath = NULL, lpDestChildPath = NULL;
    LPWSTR lpFindPath = NULL, lpLongPath = NULL;
    SIZE_T cDataLen = 0, SourcePathLength = 0, DestinationPathLength = 0;
    SIZE_T maxSourceChildLength = 0, maxDestChildLength = 0;
    SIZE_T maxFindPathLength = 0, memIO = 0;

    SourcePathLength = _strlen(SourcePath);
    DestinationPathLength = _strlen(DestinationPath);

    maxSourceChildLength = UNICODE_STRING_MAX_CHARS + 1;
    maxDestChildLength = UNICODE_STRING_MAX_CHARS + 1;
    maxFindPathLength = UNICODE_STRING_MAX_CHARS + 1;

    memIO = maxSourceChildLength * sizeof(WCHAR);
    lpSourceChildPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpSourceChildPath == NULL)
        return ERROR_OUTOFMEMORY;

    memIO = maxDestChildLength * sizeof(WCHAR);
    lpDestChildPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpDestChildPath == NULL) {
        HeapFree(g_Heap, 0, lpSourceChildPath);
        return ERROR_OUTOFMEMORY;
    }

    memIO = maxFindPathLength * sizeof(WCHAR);
    lpTemp = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
    if (lpTemp == NULL) {
        HeapFree(g_Heap, 0, lpDestChildPath);
        HeapFree(g_Heap, 0, lpSourceChildPath);
        return ERROR_OUTOFMEMORY;
    }

    _strcpy(lpTemp, SourcePath);
    _strcat(lpTemp, TEXT("*.*"));

    lpFindPath = supConvertToLongPath(lpTemp);
    if (lpFindPath == NULL)
        lpFindPath = lpTemp;

    hFindFile = FindFirstFile(lpFindPath, &data);
    if (hFindFile != INVALID_HANDLE_VALUE) {

        do {

            cDataLen = _strlen(data.cFileName);

            if ((SourcePathLength + cDataLen + 2) >= maxSourceChildLength ||
                (DestinationPathLength + cDataLen + 2) >= maxDestChildLength)
            {
                supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: path is too long"));
                uResult = ERROR_BUFFER_OVERFLOW;
                break;
            }

            RtlSecureZeroMemory(lpSourceChildPath, maxSourceChildLength * sizeof(WCHAR));
            RtlSecureZeroMemory(lpDestChildPath, maxDestChildLength * sizeof(WCHAR));

            _strcpy(lpSourceChildPath, SourcePath);
            _strcat(lpSourceChildPath, data.cFileName);

            _strcpy(lpDestChildPath, DestinationPath);
            _strcat(lpDestChildPath, data.cFileName);

            if (IsDirWithWFD(data)) {

                if (!ValidDir(data))
                    continue;

                _strcat(lpSourceChildPath, TEXT("\\"));
                _strcat(lpDestChildPath, TEXT("\\"));

                lpLongPath = supConvertToLongPath(lpDestChildPath);
                if (lpLongPath == NULL)
                    lpLongPath = lpDestChildPath;

                if (!CreateDirectory(lpLongPath, NULL)) {
                    attr = GetFileAttributes(lpLongPath);
                    if (attr == INVALID_FILE_ATTRIBUTES ||
                        ((attr & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY))
                    {
                        supConsoleWriteError(&gConsole, TEXT("SXSEXP: unable to create directory "));
                        supConsoleWriteErrorLine(&gConsole, lpDestChildPath);
                        if (lpLongPath != lpDestChildPath)
                            HeapFree(g_Heap, 0, lpLongPath);
                        uResult = ERROR_DIRECTORY;
                        break;
                    }
                }

                if (lpLongPath != lpDestChildPath)
                    HeapFree(g_Heap, 0, lpLongPath);

                uResult = ProcessTargetDirectory(lpSourceChildPath, lpDestChildPath);
                if (uResult != ERROR_SUCCESS)
                    break;
            }
            else {
                uResult = ProcessTargetFileAndWriteOutput(lpSourceChildPath, lpDestChildPath);
                if (uResult != ERROR_SUCCESS)
                    break;
            }

        } while (FindNextFile(hFindFile, &data));

        FindClose(hFindFile);
    }

    if (lpFindPath != lpTemp)
        HeapFree(g_Heap, 0, lpFindPath);

    HeapFree(g_Heap, 0, lpTemp);
    HeapFree(g_Heap, 0, lpDestChildPath);
    HeapFree(g_Heap, 0, lpSourceChildPath);

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
    _In_ LPCWSTR SourcePath,
    _In_ LPCWSTR DestinationPath
)
{
    LPWSTR lpSourceTempPath = NULL, lpDestTempPath = NULL;
    LPWSTR lpResolvedSource = NULL, lpResolvedDest = NULL;
    LPWSTR lpParentDir = NULL, lastSlash = NULL, p = NULL;
    SIZE_T memIO = 0, srcLen = 0, dstLen = 0, len = 0, parentLen = 0;
    UINT uResult = ERROR_SUCCESS;
    DWORD requiredLen;

    do {

        memIO = (UNICODE_STRING_MAX_CHARS + 1) * sizeof(WCHAR);
        lpResolvedSource = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
        lpResolvedDest = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
        if (lpResolvedSource == NULL || lpResolvedDest == NULL) {
            uResult = ERROR_OUTOFMEMORY;
            break;
        }

        //
        // Normalize source and destination paths.
        //
        requiredLen = GetFullPathName(SourcePath, (DWORD)(memIO / sizeof(WCHAR)), lpResolvedSource, NULL);
        if (requiredLen == 0 || requiredLen >= (memIO / sizeof(WCHAR))) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Failed to normalize source path"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        requiredLen = GetFullPathName(DestinationPath, (DWORD)(memIO / sizeof(WCHAR)), lpResolvedDest, NULL);
        if (requiredLen == 0 || requiredLen >= (memIO / sizeof(WCHAR))) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Failed to normalize destination path"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        //
        // Same path check.
        //
        if (_strcmpi(lpResolvedSource, lpResolvedDest) == 0) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Source and destination paths must differ"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        //
        // Overlap check.
        //
        srcLen = _strlen(lpResolvedSource);
        dstLen = _strlen(lpResolvedDest);
        if ((srcLen < dstLen && _strncmpi(lpResolvedDest, lpResolvedSource, srcLen) == 0 && lpResolvedDest[srcLen] == TEXT('\\')) ||
            (dstLen < srcLen && _strncmpi(lpResolvedSource, lpResolvedDest, dstLen) == 0 && lpResolvedSource[dstLen] == TEXT('\\')))
        {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Source and destination paths overlap"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        memIO = (UNICODE_STRING_MAX_CHARS + 1) * sizeof(WCHAR);
        lpSourceTempPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
        lpDestTempPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, memIO);
        if (lpSourceTempPath == NULL || lpDestTempPath == NULL) {
            uResult = ERROR_OUTOFMEMORY;
            break;
        }

        _strcpy(lpSourceTempPath, lpResolvedSource);
        _strcpy(lpDestTempPath, lpResolvedDest);

        len = _strlen(lpSourceTempPath);
        if (IsDir(lpSourceTempPath) && IsDir(lpDestTempPath)) {
            if (len > 0 && lpSourceTempPath[len - 1] != TEXT('\\'))
                _strcat(lpSourceTempPath, TEXT("\\"));

            len = _strlen(lpDestTempPath);
            if (len > 0 && lpDestTempPath[len - 1] != TEXT('\\'))
                _strcat(lpDestTempPath, TEXT("\\"));

            uResult = ProcessTargetDirectory(lpSourceTempPath, lpDestTempPath);
        }
        else if (!IsDir(lpSourceTempPath)) {
            parentLen = _strlen(lpDestTempPath);
            lpParentDir = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, (parentLen + 1) * sizeof(WCHAR));
            if (lpParentDir == NULL) {
                uResult = ERROR_OUTOFMEMORY;
                break;
            }

            _strcpy(lpParentDir, lpDestTempPath);
            lastSlash = NULL;
            p = lpParentDir;
            while (*p) {
                if (*p == TEXT('\\'))
                    lastSlash = p;
                ++p;
            }

            if (lastSlash && lastSlash != lpParentDir) {
                *lastSlash = 0;

                if (!supCreateDirectoryRecursive(lpParentDir)) {
                    supConsoleWriteError(&gConsole, TEXT("SXSEXP: unable to create directory "));
                    supConsoleWriteErrorLine(&gConsole, lpParentDir);
                    uResult = ERROR_DIRECTORY;
                    break;
                }
            }

            uResult = ProcessTargetFileAndWriteOutput(lpSourceTempPath, lpDestTempPath);
        }
        else {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: invalid paths specified"));
            uResult = ERROR_INVALID_PARAMETER;
        }

    } while (FALSE);

    if (lpParentDir)
        HeapFree(g_Heap, 0, lpParentDir);
    if (lpSourceTempPath)
        HeapFree(g_Heap, 0, lpSourceTempPath);
    if (lpDestTempPath)
        HeapFree(g_Heap, 0, lpDestTempPath);
    if (lpResolvedSource)
        HeapFree(g_Heap, 0, lpResolvedSource);
    if (lpResolvedDest)
        HeapFree(g_Heap, 0, lpResolvedDest);

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
UINT DCDMode(
    _In_ LPCWSTR lpCmdLine
)
{
    DWORD dwTmp = 0;
    PVOID outputBuffer = NULL;
    SIZE_T size = 0;
    SIZE_T bufferSize = 0;
    UINT uResult = ERROR_SUCCESS;
    LPWSTR szSourcePath = NULL;
    LPWSTR szSourceDeltaPath = NULL;
    LPWSTR szDestinationPath = NULL;

    bufferSize = (UNICODE_STRING_MAX_CHARS + 1) * sizeof(WCHAR);
    szSourcePath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);
    szSourceDeltaPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);
    szDestinationPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);

    do {

        if (szSourcePath == NULL || szSourceDeltaPath == NULL || szDestinationPath == NULL) {
            uResult = ERROR_OUTOFMEMORY;
            break;
        }

        //
        // Source File.
        //
        RtlSecureZeroMemory(szSourcePath, bufferSize);
        if (!GetCommandLineParam(lpCmdLine, 2, szSourcePath, UNICODE_STRING_MAX_CHARS, &dwTmp)) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Fatal error, command line param is too long"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        if ((dwTmp == 0) || (!PathFileExists(szSourcePath))) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Source Path not found"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        //
        //  Source Delta File.
        //
        RtlSecureZeroMemory(szSourceDeltaPath, bufferSize);
        if (!GetCommandLineParam(lpCmdLine, 3, szSourceDeltaPath, UNICODE_STRING_MAX_CHARS, &dwTmp)) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Fatal error, command line param is too long"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        if ((dwTmp == 0) || (!PathFileExists(szSourceDeltaPath))) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Source Delta Path not found"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        //
        //  Destination File.
        //
        RtlSecureZeroMemory(szDestinationPath, bufferSize);
        if (!GetCommandLineParam(lpCmdLine, 4, szDestinationPath, UNICODE_STRING_MAX_CHARS, &dwTmp)) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Fatal error, command line param is too long"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        if (dwTmp == 0) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Destination Path not specified"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        if (ProcessTargetFile(szSourceDeltaPath, &outputBuffer, &size, szSourcePath)) {
            if (supWriteBufferToFile(szDestinationPath, outputBuffer, (DWORD)size)) {
                supConsoleWriteLine(&gConsole, TEXT("Operation Successful"));
                uResult = ERROR_SUCCESS;
            }
            else {
                supConsoleDisplayWin32Error(&gConsole, TEXT("Error, write to file"));
                uResult = ERROR_INTERNAL_ERROR;
            }
            if (outputBuffer)
                HeapFree(g_Heap, 0, outputBuffer);
        }

    } while (FALSE);

    if (szSourcePath) HeapFree(g_Heap, 0, szSourcePath);
    if (szSourceDeltaPath) HeapFree(g_Heap, 0, szSourceDeltaPath);
    if (szDestinationPath) HeapFree(g_Heap, 0, szDestinationPath);

    return uResult;
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
    DWORD dwTmp = 0, paramId = 1;
    UINT uResult = ERROR_SUCCESS;
    LPWSTR lpCmdLine = NULL;
    LPWSTR szBuffer = NULL;
    LPWSTR szSourcePath = NULL, szDestinationPath = NULL;
    SIZE_T bufferSize = 0;

    __security_init_cookie();

    do {

        g_Heap = HeapCreate(HEAP_GROWABLE, 0, 0);
        if (g_Heap == NULL) {
            uResult = ERROR_OUTOFMEMORY;
            break;
        }

        HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
        HeapSetInformation(g_Heap, HeapEnableTerminationOnCorruption, NULL, 0);

        supConsoleInit(&gConsole);
        supConsoleWriteLine(&gConsole, T_TITLE);

        bufferSize = (UNICODE_STRING_MAX_CHARS + 1) * sizeof(WCHAR);
        szBuffer = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);
        szSourcePath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);
        szDestinationPath = (LPWSTR)HeapAlloc(g_Heap, HEAP_ZERO_MEMORY, bufferSize);
        if (szBuffer == NULL || szSourcePath == NULL || szDestinationPath == NULL) {
            uResult = ERROR_OUTOFMEMORY;
            break;
        }

        lpCmdLine = GetCommandLine();
        RtlSecureZeroMemory(szBuffer, bufferSize);
        if (!GetCommandLineParam(lpCmdLine, paramId, szBuffer, UNICODE_STRING_MAX_CHARS, &dwTmp)) {
            supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Fatal error, command line param is too long"));
            uResult = ERROR_INVALID_PARAMETER;
            break;
        }

        if (dwTmp > 0) {
            if (_strcmpi(szBuffer, L"/?") == 0) {
                supConsoleWriteLine(&gConsole, T_HELP);
                break;
            }

            if (!supInitializeMsDeltaAPI(&gMsDeltaContext)) {
                uResult = GetLastError();
                supConsoleDisplayWin32Error(&gConsole, TEXT("SXSEXP: Fatal error, failed to initialize MsDelta API"));
                break;
            }
            else {
                RtlSecureZeroMemory(szSourcePath, bufferSize);
                if (GetModuleFileName(gMsDeltaContext.hModule, szSourcePath, UNICODE_STRING_MAX_CHARS)) {
                    supConsoleWriteLine(&gConsole, TEXT("SXSEXP: Loaded MsDelta.dll"));
                    supConsoleWriteLine(&gConsole, szSourcePath);
                }
            }

            if (_strcmpi(szBuffer, L"/d") == 0) {
                uResult = DCDMode(lpCmdLine);
                break;
            }

            RtlSecureZeroMemory(szSourcePath, bufferSize);
            _strncpy(szSourcePath, UNICODE_STRING_MAX_CHARS, szBuffer, UNICODE_STRING_MAX_CHARS);

            if (!PathFileExists(szSourcePath)) {
                supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Source Path not found"));
                uResult = ERROR_INVALID_PARAMETER;
                break;
            }

            dwTmp = 0;
            paramId++;
            RtlSecureZeroMemory(szDestinationPath, bufferSize);
            if (!GetCommandLineParam(lpCmdLine, paramId, szDestinationPath, UNICODE_STRING_MAX_CHARS, &dwTmp)) {
                supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Fatal error, command line param is too long"));
                uResult = ERROR_INVALID_PARAMETER;
                break;
            }

            if (dwTmp == 0) {
                supConsoleWriteErrorLine(&gConsole, TEXT("SXSEXP: Destination Path not specified"));
                uResult = ERROR_INVALID_PARAMETER;
                break;
            }

            supConsoleWrite(&gConsole, TEXT("Processing target path:\t"));
            supConsoleWriteLine(&gConsole, szSourcePath);

            if (!supInitCabinetDecompressionAPI(&gDecompressor)) {
                supConsoleDisplayWin32Error(&gConsole, TEXT("Failed to initialize Cabinet API"));
            }

            uResult = ProcessTargetPath(szSourcePath, szDestinationPath);
        }
        else {
            supConsoleWriteLine(&gConsole, T_HELP);
        }

    } while (FALSE);

    if (szBuffer) HeapFree(g_Heap, 0, szBuffer);
    if (szSourcePath) HeapFree(g_Heap, 0, szSourcePath);
    if (szDestinationPath) HeapFree(g_Heap, 0, szDestinationPath);

    if (g_Heap != NULL)
        HeapDestroy(g_Heap);

    ExitProcess(uResult);
}
