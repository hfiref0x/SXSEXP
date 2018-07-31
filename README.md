
# SXSEXP
## Expand compressed files from WinSxS folder.

# System Requirements

x86/x64 Windows 7/8/8.1/10

# Supported file types
* DCN v1
* DCM v1
* DCS v1 (multiblock supported)
* DCD v1

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

# Authors

(c) 2016 - 2018 SXSEXP Project
