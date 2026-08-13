# Building the Starfield plugin

The production plugin requires Visual Studio 2022, CMake 3.25 or newer, vcpkg,
and a CommonLibSF checkout that exports the `CommonLibSF::CommonLibSF` CMake
target.

The reviewed dependency snapshot used CommonLibSF commit
`186654e4a39e4792c7f4353655b0763b73640d11` with commonlib-shared commit
`af93af74e9a572aa2af9b10ea9fdd73bf80b3c9c`. The checkout must also contain
the supported-runtime declarations used by `src/main.cpp` and any CMake/MSVC
compatibility fixes required by that checkout. CommonLibSF is not redistributed
in this repository.

Configure and build from a Visual Studio developer environment:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DVCPKG_ROOT=C:/vcpkg `
  -DCommonLibSFPath=C:/path/to/CommonLibSF
cmake --build build --config Release --target StarfieldHandleCapRaise --parallel
```

To stage the DLL and INI under `SFSE/Plugins` and create a ZIP:

```powershell
cmake --build build --config Release --target package_plugin
```

The live diagnostic under `tests/live_stress` accepts the same
`CommonLibSFPath` cache variable or `COMMONLIBSF_PATH` environment variable.
