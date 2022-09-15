# Demo For Bypasses

This directory contains sources for a demo that you can use to reproduce bypasses discussed in the article. The program supports seven modes: six bypasses plus one test mode for verifying that detection works when it should. Note that the demo doesn't support specifying the source file for copying and can only write a copy of itself to the provided location. This approach should be enough to test custom detections for bypasses but doesn't allow using the tool for malicious purposes.

## Usage

```
A tool for testing Sysmon's FileBlockExecutable event by Hunt & Hackett.

Usage:
  BypassBlockExecutable.exe [Mode] [File name]

Supported modes:
  0 - non-bypass -- test mode for explicitly triggering detection
  1 - create+open bypass
  2 - supersede bypass
  3 - hardlink bypass
  4 - locking bypass
  5 - mapping bypass
  6 - undelete bypass

The tool copies itself to the provided location using the specified mode.
```

## Compiling Remarks

The code depends on the Native API headers provided by the [PHNT](https://github.com/processhacker/phnt) project. Make sure to clone the repository using the `git clone --recurse-submodules` command to fetch this dependency. Alternatively, you can use `git submodule update --init` after cloning the repository.

To build the project, you need a recent version of [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). If you use [Visual Studio](https://visualstudio.microsoft.com), please refer to the built-in SDK installation. Alternatively, you can also use the standalone build environment of [EWDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#enterprise-wdk-ewdk). To compile using EWDK, use `MSBuild BypassBlockExecutable.sln /t:build /p:configuration=Release /p:platform=x64`.
