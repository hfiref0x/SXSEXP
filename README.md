
# SXSEXP
## Expand compressed files from WinSxS folder.

# System Requirements

x86/x64 Windows 7/8/8.1/10;

# Supported file types
* DCN v1
* DCM v1
* DCS v1 (multiblock supported)

# Usage
SXSEXP [/v] Source Destination
* /v - Verbose output.
* Source - Source file path.
* Destination - Destination file path.

Example: 
* sxsexp.exe srcdcn1.exe dest.exe 
* sxsexp.exe /v srcdcn1.exe dest.exe

# Build

SXSEXP comes with full source code.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

# Authors

(c) 2016 - 2017 SXSEXP Project
