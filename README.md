# IronPE - Minimal Windows PE manual loader written in Rust.

Rust PE Loader / Manual Mapping Implementation

![status](https://img.shields.io/badge/status-production-red)
![language](https://img.shields.io/badge/language-Rust-orange)
![license](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/github/v/release/iss4cf0ng/IronPE)

**IronPE** is a minimal Windows PE manual loader written in Rust for both x86 and x64 PE files.

This project is a **Rust reimplementation** of my previous project **[dotNetPELoader](https://github.com/iss4cf0ng/dotNetPELoader)**, which implemented a manual PE loader in C#.

The goal of IronPE is to explore how Windows loads Portable Executables internally and to demonstrate how this process can be implemented in Rust.

<p align="center">
  <img src="https://iss4cf0ng.github.io/images/meme/natsu_cake.jpg" width="200">
  <br>
  Waaaahhhhhhh!
</p>

<p align="center">If you find this project useful or informative, a ⭐ would be appreciated!</p>

## Disclaimer

This project is intended for **educational and research purposes only**.

It is designed to help understand:

- Windows PE internals
- Manual loading techniques
- Reverse engineering concepts

<p align="center">
    <img src="https://iss4cf0ng.github.io/images/meme/mika_rollcake_hit.png" width=200>
</p>

## Features

- Manual PE loading
- Section mapping
- Base relocations
- Import resolution
- Execute PE from memory
- x86 and x64 PE support

## Background

This project was inspired by my previous implementation:

- [dotNetPELoader](https://github.com/iss4cf0ng/dotNetPELoader) (C#)

In that project, I implemented a PE loader using .NET and WinAPI.  
IronPE rewrites the same concept in **Rust**, which provides better memory safety while still allowing low-level Windows API access.

The purpose of this project is **educational**, to better understand:

- PE file structure
- Windows loader behavior
- Manual PE mapping techniques

## How It Works
IronPE performs the following steps to execute a PE file from memory:

1. Read PE file into memory
2. Parse PE headers
3. Allocate memory using `VirtualAlloc`
4. Copy PE headers and sections
5. Apply **base relocations**
6. Resolve **imports** using `LoadLibrary` and `GetProcAddress`
7. Transfer execution to the **Original Entry Point (OEP)**

This process mimics the behavior of the Windows PE loader.

An x64 PE cannot be loaded by an x86 loader, and vice versa.

## Build
Requirements:
- Rust (`cargo`, `rustc`)
- Windows

Build the project:
```
cd IronPE
build.bat
```

## Usage
```
IronPE.exe --coffee
IronPE.exe --x86 <x86_pe_file>
IronPE.exe --x64 <x64_pe_file>
```

Example:
```
IronPE.exe --x86 Win32\mimikatz.exe
IronPE.exe --x64 x64\mimikatz.exe
```

## Demo (Running mimikatz)
### x86
<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-3-10-IronPE/1.png" width=800>
</p>
<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-3-10-IronPE/2.png" width=800>
</p>

---

### x64
<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-3-10-IronPE/3.png" width=800>
</p>

<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-3-10-IronPE/4.png" width=800>
</p>

---

### Unmatched Loader and PE Architecture (Error)
<p align="center">
    <img src="https://iss4cf0ng.github.io/images/article/2026-3-10-IronPE/5.png" width=800>
</p>
