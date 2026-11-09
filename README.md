# ManualMap

Windows AMD64 manual-mapping proof of concept. The injector, PE reader, compiler
driver, and byte converter are Java. JNA provides the Windows API bindings; only
the remote loader and the test fixtures use C++.

Design reference: [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector).
This port targets x64 only and follows that implementation's feature set:
static TLS provisioning, MSVC C++ exception support across `/EHsc`, `/EHa`, and
`/EHac` with `/MD` and `/MT`, header/section cleanup, and configurable mapping
flags. PE layout follows Microsoft's
[PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

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

`.\gradlew.bat fixtures` builds the disposable host and five copies of
`native/fixture.cpp`, one per EH/CRT combination from the reference matrix:
`fixture_ehsc_md.dll`, `fixture_eha_md.dll`, `fixture_ehsc_mt.dll`,
`fixture_eha_mt.dll`, and `fixture_ehac_mt.dll`.

Outputs:

- `build/generated-shellcode/loader.bin`: executable loader bytes.
- `build/generated-shellcode/loader.bin.java.txt`: equivalent Java byte array.
- `build/native/`: host, fixture DLLs, and intermediate objects.
- `build/install/ManualMap/`: distribution with JNA dependencies and launcher.

## Run

Pass a decimal PID and an absolute DLL path. JVM, target, and DLL must all be AMD64.

```powershell
.\gradlew.bat run --args='1234 C:\samples\fixture.dll'
# Or use the installed distribution:
.\build\install\ManualMap\bin\ManualMap.bat 1234 C:\samples\fixture.dll
```

Options after the DLL path:

| Option | Effect |
| --- | --- |
| `--reason <0..3\|attach\|detach\|thread-attach\|thread-detach>` | `DllMain` `fdwReason`, default `attach` |
| `--reserved <decimal\|0xhex>` | `DllMain` `lpReserved`, default `0` |
| `--keep-header` | retain PE headers (default: clear them) |
| `--keep-sections` | retain `.rsrc`, `.reloc`, and `.pdata` (default: clear them) |
| `--no-protections` | leave the image `RWX` instead of applying section protections |
| `--no-seh` | skip unwind-table registration and the EH stub pages |
| `--no-tls` | skip static TLS provisioning |

Run the included integration test, which launches and disposes of its own host:

```powershell
.\gradlew.bat integrationTest
```

The suite maps all five EH/CRT fixture variants and asserts the same result in
each: 30 checks (31 for `/EHa`, which adds `catch(...)` over an access
violation), plus TLS state read back from the exported `MmResultsData`. One test
reserves the DLL's preferred base in `host.exe` to force DIR64 relocations and
verifies header and `.reloc` clearing. Another maps with
`DLL_THREAD_ATTACH`/`reserved = 0x1234` and `--keep-header` semantics to check
the configurable parameters. Regular `test` runs PE validation/conversion tests
and skips process injection.

The fixture exercises, per mode:

- TLS callback on `DLL_PROCESS_ATTACH`, `thread_local` integer and string,
  per-thread isolation, and the template copy seen by a worker thread.
- `throw`/`catch` for `int`, `std::runtime_error`, a custom class by value and
  by reference, a derived class caught as its base, wrong-type fallthrough,
  `catch(...)`, `throw;`, `std::current_exception`/`rethrow_exception`, deep
  multi-frame unwind, destructor unwind, lambdas, function-pointer decay,
  sequential dispatch, nested `try`, and `std::throw_with_nested`.
- Exceptions thrown from an exported function.
- `__try`/`__except` over an access violation and integer divide by zero.
- Throw/catch and destructor unwind inside a secondary thread.

## Flow

Java validates the PE, allocates and copies headers/sections, and resolves the
loader's API pointers relative to their actual owning modules in the target.
Forwarded kernel32 exports are translated through their resolved owner. This
assumes those system modules have the same build/layout in both processes.

The C++ loader:

1. Applies DIR64 relocations (bounded block walk, rejects malformed blocks).
2. Resolves named/ordinal imports, including the absent-`OriginalFirstThunk`
   case. `_CxxThrowException` and `RtlPcToFileHeader` are replaced with stub
   pages when SEH support is enabled.
3. Registers the DLL's `.pdata` and the throw stub's own `RUNTIME_FUNCTION`
   through `RtlAddFunctionTable` **before** any DLL code runs, so exceptions
   thrown from TLS callbacks unwind correctly.
4. Provisions static TLS: Java pattern-scans ntdll's `.text` for
   `LdrpHandleTlsData` (`44 8D ? 09 [5-24] B2 01 48 8B ? 30 E8`, walked back
   over `CC` padding), the loader passes a zeroed 0x200-byte fake
   `LDR_DATA_TABLE_ENTRY` (`DllBase` at `+0x30`, `SizeOfImage` at `+0x40`,
   second argument `1`), then fires the DLL's TLS callbacks itself.
5. Calls the entry point with the configured reason and reserved pointer.
6. Reports status, Win32 error, and warning bits through the context.

Java waits for the thread, checks its exit code and status, then clears headers
and the requested sections, applies per-section protections (and `PAGE_NOACCESS`
guards between sections), flushes the instruction cache, and releases the
temporary code/context allocations. The image remains mapped until the target
exits; there is no unload command.

## Limits

- x64 only. 32-bit targets and images are rejected.
- No delay imports, CLR loading, activation contexts, or loader-list
  registration. The mapped image does not appear in `InLoadOrderModuleList`.
- Because the image is not in the loader list, new threads get a fresh TLS block
  from the template but **no `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` TLS
  callbacks**. `DllMain` thread notifications likewise do not occur.
- Load-config/CFG initialization is not performed.
- `/EHsc` treats `extern "C"` callees as non-throwing; do not throw out of one.
  The fixture's exported thrower uses C++ linkage for that reason.
- The mapped DLL's static TLS index is allocated by `LdrpHandleTlsData` and
  persists in the loader's TLS table for the process lifetime.
- DLL code runs during initialization and can create threads or retain pointers.
  On a 30-second timeout, all remote allocations remain intact while execution
  may continue. A fault, a failed `DllMain`, or a final-protection failure
  retains the image to avoid releasing memory still referenced by the target.
  Imported dependency reference counts are not rolled back after a failed load.
  Restart the disposable host to reclaim retained state.

## Statuses and warnings

Loader status (`context + 40`): `1` success, `2` missing relocations when the
image could not land at its preferred base, `3` invalid relocation, `4`
dependency/import directory failure, `5` import symbol failure, `7` `DllMain`
returned false for `DLL_PROCESS_ATTACH`. Statuses `2`-`5` occur before any DLL
code runs, so Java can release the image; `7` and timeouts retain it.

Warnings (`context + 88`): bit `1` means early unwind-table registration failed
(C++ exceptions may not unwind), bit `2` means static TLS was requested but
`LdrpHandleTlsData` was unavailable or returned a failure NTSTATUS. Warnings are
reported on stderr and do not fail the mapping.

## Context layout

The 104-byte context is explicit on both sides (`static_assert` in the loader):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | image base |
| 8 | 8 | `LoadLibraryA` |
| 16 | 8 | `GetProcAddress` |
| 24 | 8 | `RtlAddFunctionTable` |
| 32 | 8 | `RtlDeleteFunctionTable` |
| 40 | 4 | status |
| 44 | 4 | Win32 error |
| 48 | 8 | `GetLastError` |
| 56 | 8 | `LdrpHandleTlsData` |
| 64 | 8 | `_CxxThrowException` stub page |
| 72 | 8 | `RtlPcToFileHeader` trampoline page |
| 80 | 4 | `DllMain` reason |
| 84 | 4 | feature flags (bit 1 SEH, bit 2 TLS) |
| 88 | 4 | warning bits |
| 92 | 4 | reserved |
| 96 | 8 | `DllMain` reserved |

## Standalone converter

After `installDist`, the tool also runs directly with the distribution classpath:

```powershell
java -cp 'build/install/ManualMap/lib/*' org.t1xel.tools.ShellcodeTool extract build/native/loader.exe build/loader.bin
java -cp 'build/install/ManualMap/lib/*' org.t1xel.tools.ShellcodeTool bytes build/loader.bin
```

Compile loader changes through Gradle so the freestanding compiler/linker flags
remain consistent. Generated native products and byte arrays stay under `build/`.
