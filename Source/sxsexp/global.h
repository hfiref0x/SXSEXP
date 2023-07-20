/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.40
*
*  DATE:        19 July 2023
*
*  Global header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1920)
#pragma comment(linker,"/merge:_RDATA=.rdata")
#endif
#endif

#include <Windows.h>
#include <msdelta.h>
#include <compressapi.h>
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "sup.h"

#pragma comment(lib, "msdelta.lib")

extern HANDLE g_Heap;
