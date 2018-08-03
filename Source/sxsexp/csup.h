/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       CSUP.H
*
*  VERSION:     1.30
*
*  DATE:        30 July 2018
*
*  Support routines header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(lib, "msdelta.lib")

typedef enum _CFILE_TYPE {
    ftDCD = 1,
    ftDCN,
    ftDCH,
    ftDCM,
    ftDCS,
    ftDCX,
    ftMZ,
    ftUnknown,
    ftMax
} CFILE_TYPE;

typedef struct _DCN_HEADER {
    DWORD Signature; //DCN v1
    BYTE Data[1]; //Intra Package Delta 
} DCN_HEADER, *PDCN_HEADER;

typedef struct _DCM_HEADER {
    DWORD Signature; //DCM v1
    BYTE Data[1]; //Intra Package Delta, need wcp manifest to unpack
} DCM_HEADER, *PDCM_HEADER;

typedef struct _DCD_HEADER {
    DWORD Signature; //DCD v1
    DWORD Unknown1;
    DWORD Unknown2;
    BYTE Data[1]; //Intra Package Delta
} DCD_HEADER, *PDCD_HEADER;

typedef struct _DCH_HEADER {
    DWORD Signature; //DCH v1
    DWORD Unknown1;
    DWORD Unknown2;
} DCH_HEADER, *PDCH_HEADER;

typedef struct _DCS_HEADER {
    DWORD Signature; //DCS v1
    DWORD NumberOfBlocks;
    DWORD UncompressedFileSize;
    BYTE FirstBlock[1];
} DCS_HEADER, *PDCS_HEADER;

typedef struct _DCS_BLOCK {
    DWORD CompressedBlockSize;
    DWORD DecompressedBlockSize;
    BYTE CompressedData[1];
} DCS_BLOCK, *PDCS_BLOCK;

CFILE_TYPE GetTargetFileType(
    _In_ VOID *FileBuffer
);

_Success_(return == TRUE)
BOOL ProcessFileMZ(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
);

_Success_(return == TRUE)
BOOL ProcessFileDCN(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
);

_Success_(return == TRUE)
BOOL ProcessFileDCS(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
);

_Success_(return == TRUE)
BOOL ProcessFileDCM(
    _In_ PVOID SourceFile,
    _In_ SIZE_T SourceFileSize,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
);

_Success_(return == TRUE)
BOOL ProcessFileDCD(
    _In_ PVOID DeltaSourceFile,
    _In_ SIZE_T DeltaSourceFileSize,
    _In_ LPWSTR lpSourceFileName,
    _Out_ PVOID *OutputFileBuffer,
    _Out_ PSIZE_T OutputFileBufferSize
);
