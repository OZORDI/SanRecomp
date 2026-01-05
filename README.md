<p align="center">
    <h1 align="center">San Recompiled</h1>
    <p align="center"><em>GTA V Xbox 360 Static Recompilation Project</em></p>
</p>

---

> [!CAUTION]
> This recompilation is in early development and is NOT meant for public use. This is a work-in-progress fork based on the MarathonRecomp framework.

San Recompiled is an unofficial PC port of the Xbox 360 version of Grand Theft Auto V created through the process of static recompilation. The port aims to offer Windows, Linux, and macOS support.

**This project does not include any game assets. You must provide the files from your own legally acquired copy of the game to install or build San Recompiled.**

[XenonRecomp](https://github.com/sonicnext-dev/XenonRecomp) is the main recompiler used for converting the game's original PowerPC code into compatible C++ code. The development of this recompiler was directly inspired by [N64: Recompiled](https://github.com/N64Recomp/N64Recomp), which was used to create [Zelda 64: Recompiled](https://github.com/Zelda64Recomp/Zelda64Recomp).

## Table of Contents

- [Project Status](#project-status)
- [Installation](#installation)
- [Building](#building)
- [Documentation](#documentation)

## Project Status

This project is in **early development**. Current progress:

### Completed
- [x] XenonRecomp integration for PowerPC → C++ translation
- [x] Cross-platform build system (Windows, Linux, macOS)
- [x] Installer wizard with ISO/folder/XContent support
- [x] Platform-specific install directory support

### In Progress
- [ ] XenosRecomp integration for Xenos → HLSL shader conversion
- [ ] RAGE engine structure reverse engineering
- [ ] GPU/rendering pipeline implementation
- [ ] Game-specific patches and fixes
- [ ] Audio system implementation
- [ ] Save data handling
- [ ] Input remapping for GTA V controls

## Installation

### Platform Install Directories

| Platform | Install Directory |
|----------|-------------------|
| Windows | `%LOCALAPPDATA%\SanRecomp\` |
| Linux | `~/.local/share/SanRecomp/` |
| macOS | `~/Library/Application Support/SanRecomp/` |

### Game Files Required

You need a legal copy of GTA V for Xbox 360. Supported formats:
- Xbox 360 disc images (`.iso`)
- Extracted game folders
- XContent packages

See [Dumping Guide](/docs/DUMPING-en.md) for detailed extraction instructions.

### Launch Arguments

| Argument | Description |
|----------|-------------|
| `--install` | Force reinstallation (useful if game files were modified) |
| `--install-dlc` | Force DLC installation only |
| `--install-check` | Verify file integrity |

## Building

[Check out the building instructions here](/docs/BUILDING.md).

### Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/OZORDI/SanRecomp.git
cd SanRecomp

# Add game files to SanRecompLib/private/
# - default.xex
# - Files from GTA V Xbox 360

# Configure and build (macOS example)
cmake . --preset macos-release
cmake --build ./out/build/macos-release --target SanRecomp
```

## Documentation

| Document | Description |
|----------|-------------|
| [Building Guide](/docs/BUILDING.md) | Build instructions for all platforms |
| [Dumping Guide](/docs/DUMPING-en.md) | How to extract game files from Xbox 360 |
