# zapret-win-gui

Portable single-EXE Windows GUI for [zapret](https://github.com/bol-van/zapret) DPI bypass tool.

## Features

- **Single portable executable** — all zapret binaries embedded as resources
- **System tray** — runs invisibly, click tray icon to open settings
- **Windows service** — checkbox to install/uninstall as auto-start service
- **Preset strategies** — common DPI bypass configurations included
- **Portable config** — INI file stored next to the exe

## Building

Requires:
- CMake 3.20+
- Visual Studio 2022+ (or Build Tools) with C/C++ workload
- Windows SDK 10.0+
- Internet connection (to fetch zapret-win-bundle from GitHub)

```powershell
cmake -B build -G "Visual Studio 18 2025" -A x64
cmake --build build --config Release
```

Output: `build/bin/Release/zapret-gui.exe`

## How it works

1. Pre-built zapret binaries are downloaded from [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle) during CMake configure
2. They are embedded into the exe as RCDATA resources via the `.rc` file
3. At runtime, binaries are extracted to `%TEMP%\zapret-gui\` (or `%PROGRAMDATA%\zapret-gui\` for service mode)
4. `winws.exe` is launched as a child process with your configured arguments

## License

MIT
