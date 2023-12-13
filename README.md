
# SXSEXP
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
SXSEXP < Source File > < Destination File >

SXSEXP < Source Directory > < Destination Directory >

SXSEXP /d < Source File > < Source Delta File > < Destination File >

Example: 
* sxsexp.exe srcdcn1.exe dest.exe 
* sxsexp.exe C:\windows\winsxs D:\winsxs
* sxsexp.exe /d c:\test\Display.dll.src c:\test\Display.dcd.delta C:\test\Display.result.dll

# Build

SXSEXP comes with full source code written in C.
In order to build from source you need Microsoft Visual Studio 2019 and later versions.

# Newest MsDelta changes

Since apprx. Windows 11 MS introduced updated version of MsDelta compression library that comes as part of cumulative update. This library called "UpdateCompression.dll" 
and it is a new version of Windows built-in MsDelta.dll with (besides of other improvements) only support to in-memory operations compared to old MsDelta.dll that can also work directly with files.

If you are having trouble with expanding files try using updatecompression.dll instead of default msdelta.dll. Simple rename updatecompression.dll to msdelta.dll and drop it to
the same directory where sxsexp located. See [#6](https://github.com/hfiref0x/SXSEXP/issues/6) for more information.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v142 for Visual Studio 2019;
  * v143 for Visual Studio 2022.
* Windows SDK 10 or above must be installed.

# Authors

(c) 2016 - 2023 SXSEXP Project
