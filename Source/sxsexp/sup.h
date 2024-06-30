/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       SUP.H
*
*  VERSION:     1.41
*
*  DATE:        10 Dec 2023
*
*  Program support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define PathFileExists(lpszPath) (GetFileAttributes(lpszPath) != (DWORD)-1)
#define IsDir(lpszPath)          ((GetFileAttributes(lpszPath) & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
#define IsDirWithWFD(data)       ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ==  FILE_ATTRIBUTE_DIRECTORY)
#define ValidDir(data)           (_strcmpi(data.cFileName, TEXT(".")) && _strcmpi(data.cFileName, TEXT("..")))

typedef enum _CFILE_TYPE {
    ftDCD = 1,
    ftDCN,
    ftDCH,
    ftDCM,
    ftDCS,
    ftDCX,
    ftUnknown,
    ftMax
} CFILE_TYPE;

//
// DC types
//

typedef struct _DCN_HEADER {
    DWORD Signature; //DCN v1
    BYTE Data[1]; //Intra Package Delta, not a part of this structure 
} DCN_HEADER, * PDCN_HEADER;

typedef struct _DCM_HEADER {
    DWORD Signature; //DCM v1
    BYTE Data[1]; //Intra Package Delta, need wcp manifest to unpack, not a part of this structure
} DCM_HEADER, * PDCM_HEADER;

typedef struct _DCD_HEADER {
    DWORD Signature; //DCD v1
    DWORD Unknown1;
    DWORD Unknown2;
    BYTE Data[1]; //Intra Package Delta, not a part of this structure
} DCD_HEADER, * PDCD_HEADER;

typedef struct _DCH_HEADER {
    DWORD Signature; //DCH v1
    DWORD Unknown1;
    DWORD Unknown2;
} DCH_HEADER, * PDCH_HEADER;

typedef struct _DCS_HEADER {
    DWORD Signature; //DCS v1
    DWORD NumberOfBlocks;
    DWORD UncompressedFileSize;
    BYTE FirstBlock[1]; //not a part of this structure
} DCS_HEADER, * PDCS_HEADER;

typedef struct _DCS_BLOCK {
    DWORD Size; //part of next DCS_BLOCK included
    DWORD DecompressedBlockSize;
    BYTE Data[1]; //not a part of this structure
} DCS_BLOCK, * PDCS_BLOCK;

typedef BOOL(WINAPI* pfnCreateDecompressor)(
    _In_ DWORD Algorithm,
    _In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
    _Out_ PDECOMPRESSOR_HANDLE DecompressorHandle
    );

typedef BOOL(WINAPI* pfnDecompress)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle,
    _In_reads_bytes_opt_(CompressedDataSize) PVOID CompressedData,
    _In_ SIZE_T CompressedDataSize,
    _Out_writes_bytes_opt_(UncompressedBufferSize) PVOID UncompressedBuffer,
    _In_ SIZE_T UncompressedBufferSize,
    _Out_opt_ PSIZE_T UncompressedDataSize
    );

typedef BOOL(WINAPI* pfnCloseDecompressor)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle
    );

typedef struct _SUP_DECOMPRESSOR {
    BOOL Initialized;
    pfnCloseDecompressor CloseDecompressor;
    pfnCreateDecompressor CreateDecompressor;
    pfnDecompress Decompress;
} SUP_DECOMPRESSOR, * PSUP_DECOMPRESSOR;

typedef BOOL (WINAPI* pfnApplyDeltaB)(
    _In_ DELTA_FLAG_TYPE ApplyFlags,
    _In_ DELTA_INPUT Source,
    _In_ DELTA_INPUT Delta,
    _Out_ LPDELTA_OUTPUT lpTarget);

typedef BOOL (WINAPI* pfnDeltaFree)(
    _In_ LPVOID lpMemory);

typedef BOOL (WINAPI* pfnGetDeltaInfoB)(
    _In_ DELTA_INPUT Delta,
    _Out_ LPDELTA_HEADER_INFO lpHeaderInfo);

typedef struct _SUP_DELTA_COMPRESSION {
    HMODULE hModule;
    pfnApplyDeltaB ApplyDeltaB;
    pfnDeltaFree DeltaFree;
    pfnGetDeltaInfoB GetDeltaInfoB;
} SUP_DELTA_COMPRESSION, * PSUP_DELTA_COMPRESSION;


//
// CONSOLE START
//

typedef enum _SUP_CONSOLE_MODE {
    ConsoleModeDefault = 0,
    ConsoleModeFile
} SUP_CONSOLE_MODE;

typedef struct _SUP_CONSOLE {
    HANDLE OutputHandle;
    HANDLE InputHandle;
    SUP_CONSOLE_MODE Mode;
} SUP_CONSOLE, * PSUP_CONSOLE;

VOID supConsoleInit(
    _Inout_ PSUP_CONSOLE Console);

VOID supConsoleClear(
    _In_ PSUP_CONSOLE Console);

VOID supConsoleWriteWorker(
    _In_ PSUP_CONSOLE Console,
    _In_ LPCWSTR lpText,
    _In_ BOOL UseReturn);

#define supConsoleWrite(Console, lpText) supConsoleWriteWorker(Console, lpText, FALSE)
#define supConsoleWriteLine(Console, lpText) supConsoleWriteWorker(Console, lpText, TRUE)

VOID supConsoleDisplayWin32Error(
    _In_ PSUP_CONSOLE Console,
    _In_ LPCWSTR lpText);

//
// CONSOLE END
//
BOOL supInitializeMsDeltaAPI(
    _Inout_ PSUP_DELTA_COMPRESSION MsDeltaContext);

BOOL supInitCabinetDecompressionAPI(
    _Inout_ PSUP_DECOMPRESSOR Decompressor);

CFILE_TYPE supGetFileType(
    _In_ PVOID FileBuffer,
    _In_ ULONG fileSize);

LPWSTR supPrintHash(
    _In_reads_bytes_(Length) LPBYTE Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN UpcaseHex);

BOOL supWriteBufferToFile(
    _In_ LPCWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize);

VOID supPrintDeltaHeaderInfo(
    _In_ PSUP_CONSOLE Console,
    _In_ LPDELTA_HEADER_INFO DeltaHeaderInfo);

BOOL supMapInputFile(
    _In_ LPCWSTR FileName,
    _Out_ PULONG FileSize,
    _Out_ PVOID* BaseAddress);
