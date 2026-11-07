# ManualMap

Windows AMD64 manual-mapping proof of concept. The injector, PE reader, compiler
driver, and byte converter are Java. JNA provides the Windows API bindings; only
the remote loader and the test fixtures use C++.

Design reference: [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector).
This is a smaller independent implementation, with the limits listed below.
PE layout follows Microsoft's [PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## Build

Requirements: Windows x64, an AMD64 JDK 21, MSVC x64 C++ build tools, and a
Windows SDK. A full Visual Studio install or Build Tools install works.
The Java driver discovers MSVC using `vswhere`. Set `MANUALMAP_VCVARS64` to the
absolute path of `vcvars64.bat` to override discovery.

```powershell
.\gradlew.bat build
.\gradlew.bat installDist
```

Gradle compiles `native/loader.cpp`, links a freestanding PE, extracts its `.text`,
and packages `loader.bin` as a Java resource. No Python, assembly source, objcopy,
or hand-maintained instruction array is required. Linker-generated read-only
data is merged into `.text`, and the converter prepends a relative jump to the
PE entry point. It rejects imports, base relocations, and unexpected sections.
`.pdata` is deliberately excluded; the stub itself must not throw exceptions.
This extractor is intended for the included freestanding stub, rather than
arbitrary compiled C++ programs.

Outputs:

- `build/generated-shellcode/loader.bin`: executable loader bytes.
- `build/generated-shellcode/loader.bin.java.txt`: equivalent Java byte array.
- `build/install/ManualMap/`: distribution with JNA dependencies and launcher.

## Run

Pass a decimal PID and an absolute DLL path. JVM, target, and DLL must all be AMD64.

```powershell
.\gradlew.bat run --args='1234 C:\samples\fixture.dll'
# Or use the installed distribution:
.\build\install\ManualMap\bin\ManualMap.bat 1234 C:\samples\fixture.dll
```

Run the included integration test, which launches and disposes of its own host:

```powershell
.\gradlew.bat integrationTest
```

It reserves the DLL's preferred base in `host.exe`, forcing DIR64 relocations.
`fixture.dll` writes its process ID through a relocated absolute pointer and
signals an event using imported APIs. The test reads back the exported state
and checks the host's exit code. Regular `test` runs PE validation/conversion
tests and skips process injection.

## Flow and limits

Java validates the PE, allocates and copies headers/sections, and resolves the
loader's API pointers relative to their actual owning modules in the target.
Forwarded kernel32 exports are translated through their resolved owner. This
assumes those system modules have the same build/layout in both processes.

The C++ loader applies DIR64 relocations, resolves named/ordinal imports
(including the absent-OriginalFirstThunk case), registers the DLL's x64 unwind
table, runs TLS callbacks, and invokes `DllMain(DLL_PROCESS_ATTACH)`. Java waits
for the thread, checks its exit code and status, applies section protections,
and releases the temporary code/context allocations. Headers stay readable.
The image remains mapped until the target exits; there is no unload command.

This PoC does not implement static TLS storage, thread notifications, delay
imports, CLR loading, activation contexts, loader-list registration, or full
Windows load-config/CFG initialization. Static TLS, delay imports, and CLR
images are rejected. DLLs needing other loader services may fail; start with
the included minimal fixture. Unwind registration supports ordinary table-based
unwinding; it does not provide full MSVC C++ runtime module discovery.

DLL code runs during initialization and can create threads or retain pointers.
On a 30-second timeout, all remote allocations remain intact while execution
may continue. A fault, a failed `DllMain`, or a final-protection failure retains
the image to avoid releasing memory still referenced by the target. Imported
dependency reference counts are not rolled back after a failed load. Restart
the disposable host to reclaim retained state.

Loader statuses: `1` success, `2` missing relocations, `3` invalid relocation,
`4` dependency/import directory failure, `5` import symbol failure, `6` unwind
registration failure, `7` `DllMain` returned false. Import failures include the
remote Win32 error.

The 56-byte context is explicit on both sides: image at `0`, LoadLibraryA at `8`,
GetProcAddress at `16`, RtlAddFunctionTable at `24`, RtlDeleteFunctionTable at `32`,
status/error DWORDs at `40`/`44`, and GetLastError at `48`.

## Standalone converter

After `installDist`, the tool also runs directly with the distribution classpath:

```powershell
java -cp 'build/install/ManualMap/lib/*' org.t1xel.tools.ShellcodeTool extract build/native/loader.exe build/loader.bin
java -cp 'build/install/ManualMap/lib/*' org.t1xel.tools.ShellcodeTool bytes build/loader.bin
```

Compile loader changes through Gradle so the freestanding compiler/linker flags
remain consistent. Generated native products and byte arrays stay under `build/`.
