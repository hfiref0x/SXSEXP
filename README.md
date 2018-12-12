
# SXSEXP
## Expand compressed files from WinSxS folder.

# System Requirements

x86/x64 Windows 7/8/8.1/10

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
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1 (Note that Windows 8.1 SDK must be installed);
  * If v141 then select 10.0.17134.0 (Note that Windows 10.0.17134 SDK must be installed). 

# Authors

(c) 2016 - 2018 SXSEXP Project
