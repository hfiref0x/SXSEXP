/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CSUP.H
*
*  VERSION:     1.10
*
*  DATE:        14 June 2016
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
    VOID *FileBuffer
);

BOOL ProcessFileMZ(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
);

BOOL ProcessFileDCN(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
);

BOOL ProcessFileDCS(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
);

BOOL ProcessFileDCM(
    PVOID SourceFile,
    SIZE_T SourceFileSize,
    PVOID *OutputFileBuffer,
    PSIZE_T OutputFileBufferSize
);
