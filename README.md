# SXSEXP
[![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FSXSEXP&countColor=%23263759&style=flat)](https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FSXSEXP)

## Expand compressed files from WinSxS folder.

# System Requirements

x86/x64 Windows 7/8/8.1/10/11

# Supported file types
* DCN v1
* DCM v1
* DCS v1
* DCD v1

# Type descriptions
* Header Sign: 0x44 0x43 0x4E 0x01, DCN 01 (packed IPD PA30)
* Header Sign: 0x44 0x43 0x4D 0x01, DCM 01 (packed IPD PA30, source manifest required, wcp)
* Header Sign: 0x44 0x43 0x53 0x01, DCS 01 (packed LZMS, can have multiple blocks)
* Header Sign: 0x44 0x43 0x44 0x01, DCD 01 (packed IPD PA30, delta, source file required)
* Header Sign: 0x44 0x43 0x48 0x01, DCH 01 (not packed, header only)
* Header Sign: 0x44 0x43 0x58 0x01, DCX 01 (unknown, only supported by Windows 10)

# Usage
SXSEXP SourceFile DestinationFile

SXSEXP SourceDirectory DestinationDirectory

SXSEXP /d SourceFile SourceDeltaFile DestinationFile

Example: 
* sxsexp.exe srcdcn1.exe dest.exe 
* sxsexp.exe C:\windows\winsxs D:\winsxs
* sxsexp.exe /d c:\test\Display.dll.src c:\test\Display.dcd.delta C:\test\Display.result.dll

# Build

SXSEXP comes with full source code written in C.
In order to build from source, you need Microsoft Visual Studio 2019 or later versions.

# Newest MsDelta changes

Since approximately Windows 11, Microsoft introduced an updated version of the MsDelta compression library that comes as part of cumulative updates. This library is called "UpdateCompression.dll" and is a new version of the Windows built-in MsDelta.dll with (besides other improvements) support only for in-memory operations, compared to the old MsDelta.dll that can also work directly with files.

If you are having trouble expanding files, try using updatecompression.dll instead of the default msdelta.dll. Simply rename updatecompression.dll to msdelta.dll and place it in the same directory where sxsexp is located. See [#6](https://github.com/hfiref0x/SXSEXP/issues/6) for more information.

## Instructions

* Select Platform ToolSet first for the project in the solution you want to build (Project->Properties->General): 
  * v142 for Visual Studio 2019;
  * v143 for Visual Studio 2022.
* Windows SDK 10 or above must be installed.

# Authors

(c) 2016 - 2025 SXSEXP Project
