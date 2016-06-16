/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       COMPRESS.H
*
*  VERSION:     1.10
*
*  DATE:        14 June 2016
*
*  Compression support header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef BOOL (WINAPI *pfnCreateDecompressor)(
    _In_ DWORD Algorithm,
    _In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
    _Out_ PDECOMPRESSOR_HANDLE DecompressorHandle
    );

typedef BOOL (WINAPI *pfnDecompress)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle,
    _In_reads_bytes_opt_(CompressedDataSize) PVOID CompressedData,
    _In_ SIZE_T CompressedDataSize,
    _Out_writes_bytes_opt_(UncompressedBufferSize) PVOID UncompressedBuffer,
    _In_ SIZE_T UncompressedBufferSize,
    _Out_opt_ PSIZE_T UncompressedDataSize
    );

typedef BOOL (WINAPI *pfnCloseDecompressor)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle
    );
