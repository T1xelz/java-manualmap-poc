# ManualMap

Windows manual-mapping proof of concept for AMD64 and x86 (WOW64) targets. The
injector, PE reader, compiler driver, and byte converter are Java. JNA provides
the Windows API bindings; only the remote loaders and the test fixtures use C++.

Design reference: [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector).
The x64 path follows that implementation's full feature set: static TLS
provisioning, MSVC C++ exception support across `/EHsc`, `/EHa`, and `/EHac`
with `/MD` and `/MT`, header/section cleanup, and configurable mapping flags.
The x86 path follows the reference's deliberately smaller x86 matrix:
mapping, imports, and relocations only. PE layout follows Microsoft's
[PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

| Feature | x64 (PE32+) | x86 (PE32) |
| --- | --- | --- |
| Manual mapping, DllMain | yes | yes |
| Imports, base relocations | DIR64 | HIGHLOW |
| Static TLS | yes | no |
| SEH / `.pdata` registration | yes | no |
| MSVC C++ exceptions (`/EH*`) | yes | no |
| Header/section clearing, protections | yes | yes |

## Project layout

- `library/src/main/java`: reusable API and implementation (package `org.t1xel`).
- `library/src/main/cpp`: native loader sources.
- `library/src/tools/java`: build-time compiler/converter, excluded from the runtime JAR.
- `library/src/test/java`: PE parsing and API contract tests.
- `library/src/test/cpp`: disposable native hosts and fixtures.
- `library/src/integrationTest/java`: opt-in process integration tests.
- `cli/src/main/java`: argument parsing, console output and exit codes.
- `gradle/wrapper`: committed wrapper; IDE state and build outputs are ignored.

Root `build` and `check` aggregate both modules. Integration tests run only with
`:library:integrationTest`. Unit tests also verify generated loader resources,
so they currently require Windows and MSVC. After changing the installed MSVC/SDK,
use `clean build` to regenerate native resources.

## Library usage

The library artifact is `library/build/libs/manualmap-1.0.jar`; it includes both
loader resources, but no CLI or compiler tools. A sources JAR is built alongside it.
JNA is a runtime dependency, so prefer a published dependency over copying a
single JAR. Publish locally with:

```powershell
.\gradlew.bat :library:publishToMavenLocal
```

In a consuming Gradle project (JDK 21 or newer):

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("org.t1xel:manualmap:1.0")
}
```

Public entry points remain `ManualMapper` and `MappingOptions`. The existing
`map(...)` methods return an address; `mapResult(...)` additionally returns an
immutable list of diagnostic messages. Neither method prints or exits the JVM.
A mapper may be reused concurrently: every invocation has its own diagnostics.

```java
import org.t1xel.ManualMapper;
import org.t1xel.MappingException;
import org.t1xel.MappingResult;

import java.nio.file.Path;

try {
    MappingResult result = new ManualMapper().mapResult(pid, Path.of(dllPath));
    // result.address(): mapped image address
    // result.warnings(): non-fatal loader/cleanup diagnostics
} catch (MappingException error) {
    // error.kind(): VALIDATION, UNSUPPORTED_PLATFORM, IO, NATIVE_CALL, LOADER, WAIT
    // error.operation() / error.nativeError(): optional Win32 call details
    // error.getCause(): original validation, I/O or native-call exception
}
```

`MappingException` extends `IOException`, preserving existing I/O catch blocks.
Validation failures from mapping now use `Kind.VALIDATION` instead of escaping as
`IllegalArgumentException`; invalid `MappingOptions` still fail immediately in
the constructor/builder. Diagnostic strings are for display, not parsing.
Warnings are returned on successful calls; a failed call throws its exception.
Memory retention and unload limitations below still apply to library callers.

## Build

Requirements: Windows x64, an AMD64 JDK 21, MSVC x86/x64 C++ build tools, and a
Windows SDK. A full Visual Studio install or Build Tools install works.
The Java driver discovers MSVC using `vswhere`. Set `MANUALMAP_VCVARS64` or
`MANUALMAP_VCVARS32` to the absolute path of `vcvars64.bat` / `vcvars32.bat` to
override discovery.

```powershell
.\gradlew.bat build
.\gradlew.bat :cli:installDist
```

Gradle compiles `library/src/main/cpp/loader.cpp` with `vcvars64`, links a freestanding PE,
extracts its `.text`, and packages `loader64.bin` as a Java resource. It does the
same for `library/src/main/cpp/loader32.cpp` with `vcvars32`, producing `loader32.bin`. No
Python, assembly source, objcopy, or hand-maintained instruction array is
required. Linker-generated read-only data is merged into `.text`, and the
converter prepends a relative jump to the PE entry point. It rejects imports,
base relocations, and unexpected sections. This extractor is intended for the
included freestanding stubs, rather than arbitrary compiled C++ programs.

`.\gradlew.bat :library:fixtures` builds the disposable hosts and fixtures:

- x64: five copies of `library/src/test/cpp/fixture.cpp`, one per EH/CRT combination from the
  reference matrix: `fixture_ehsc_md.dll`, `fixture_eha_md.dll`,
  `fixture_ehsc_mt.dll`, `fixture_eha_mt.dll`, `fixture_ehac_mt.dll`, plus
  `host.exe`.
- x86: `library/src/test/cpp/fixture32.cpp` as `fixture32.dll` and `host32.exe`, both
  freestanding (`/NODEFAULTLIB`, no CRT, no TLS, no SEH, no C++ exceptions).

Outputs:

- `library/build/generated-shellcode/loader64.bin` / `loader32.bin`: executable loader bytes.
- `library/build/generated-shellcode/*.java.txt`: equivalent Java byte arrays.
- `library/build/native/`: hosts, fixture DLLs, and intermediate objects.
- `cli/build/install/ManualMap/`: distribution with JNA dependencies and launcher.

## Run

Pass a decimal PID and an absolute DLL path. A PE32+ DLL requires a native AMD64
target; a PE32 DLL requires a WOW64 (x86) target. The JVM itself is always AMD64.

```powershell
.\gradlew.bat :cli:run --args='1234 C:\samples\fixture.dll'
# Or use the installed distribution:
.\cli\build\install\ManualMap\bin\ManualMap.bat 1234 C:\samples\fixture.dll
```

Options after the DLL path:

| Option | Effect |
| --- | --- |
| `--reason <0..3\|attach\|detach\|thread-attach\|thread-detach>` | `DllMain` `fdwReason`, default `attach` |
| `--reserved <decimal\|0xhex>` | `DllMain` `lpReserved`, default `0` (truncated to 32 bits on x86) |
| `--keep-header` | retain PE headers (default: clear them) |
| `--keep-sections` | retain `.rsrc`, `.reloc`, and `.pdata` (default: clear them) |
| `--no-protections` | leave the image `RWX` instead of applying section protections |
| `--no-seh` | x64 only: skip unwind-table registration and the EH stub pages |
| `--no-tls` | x64 only: skip static TLS provisioning |

Run the included integration test, which launches and disposes of its own hosts:

```powershell
.\gradlew.bat :library:integrationTest
```

The x64 suite maps all five EH/CRT fixture variants and asserts the same result
in each: 30 checks (31 for `/EHa`, which adds `catch(...)` over an access
violation), plus TLS state read back from the exported `MmResultsData`. One test
reserves the DLL's preferred base in `host.exe` to force DIR64 relocations and
verifies header and `.reloc` clearing. Another maps with
`DLL_THREAD_ATTACH`/`reserved = 0x1234` and `--keep-header` semantics.

The x86 suite maps `fixture32.dll` into `host32.exe` and verifies HIGHLOW
relocations, kernel32 imports, `MmAttached`/`MmAttachedPointer`, header and
`.reloc` clearing, configured reason/reserved values, and both cross-architecture
rejections (x86 DLL into an AMD64 process, x64 DLL into a WOW64 process).

Regular `test` runs PE32/PE32+ validation and conversion tests and skips process
injection.

## Flow

Java parses the PE, selects the matching loader resource by machine, allocates
and copies headers/sections, and resolves the loader's API pointers.

For x64, pointers are resolved relative to their actual owning modules in the
target, and forwarded kernel32 exports are translated through their resolved
owner. This assumes those system modules have the same build/layout in both
processes.

For x86, local function addresses are unusable because the JVM is 64-bit while
the target is WOW64. Java enumerates the target's 32-bit module list
(`TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32`) and parses the remote PE export
tables for `LoadLibraryA`, `GetProcAddress`, and `GetLastError`, following
forwarded exports (API-set forwarders fall back to `KERNELBASE.dll`).

The x64 loader:

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

The x86 loader applies HIGHLOW relocations, resolves 32-bit imports, warns when
the image carries a TLS directory (unsupported on this path), and calls the
entry point. It does not touch `.pdata`, unwind tables, or TLS callbacks.

Java waits for the thread, checks its exit code and status, then clears headers
and the requested sections, applies per-section protections (and `PAGE_NOACCESS`
guards between sections), flushes the instruction cache, and releases the
temporary code/context allocations. The image remains mapped until the target
exits; there is no unload command.

## Limits

- PE32+ images require a native AMD64 process; PE32 images require a WOW64
  process. Mixed combinations are rejected before allocation.
- x86 has no static TLS, no SEH/unwind registration, and no C++ exception
  support, matching the reference's x86 matrix. An x86 image with a TLS
  directory maps with warning bit `4`; its TLS callbacks do not run.
- No delay imports, CLR loading, activation contexts, or loader-list
  registration. The mapped image does not appear in `InLoadOrderModuleList`.
- Because the image is not in the loader list, new threads get a fresh TLS block
  from the template but **no `DLL_THREAD_ATTACH`/`DLL_THREAD_DETACH` TLS
  callbacks**. `DllMain` thread notifications likewise do not occur.
- Load-config/CFG initialization is not performed.
- `/EHsc` treats `extern "C"` callees as non-throwing; do not throw out of one.
  The x64 fixture's exported thrower uses C++ linkage for that reason.
- The mapped DLL's static TLS index is allocated by `LdrpHandleTlsData` and
  persists in the loader's TLS table for the process lifetime (x64 only).
- x86 export forwarding through an unknown API-set name relies on
  `KERNELBASE.dll` being present in the target, which is true for normal WOW64
  processes.
- DLL code runs during initialization and can create threads or retain pointers.
  On a 30-second timeout, all remote allocations remain intact while execution
  may continue. A fault, a failed `DllMain`, or a final-protection failure
  retains the image to avoid releasing memory still referenced by the target.
  Imported dependency reference counts are not rolled back after a failed load.
  Restart the disposable host to reclaim retained state.

## Statuses and warnings

Statuses are identical on both architectures; only the context offset differs
(x64 `+40`, x86 `+12`): `1` success, `2` missing relocations when the image
could not land at its preferred base, `3` invalid relocation, `4`
dependency/import directory failure, `5` import symbol failure, `7` `DllMain`
returned false for `DLL_PROCESS_ATTACH`. Statuses `2`-`5` occur before any DLL
code runs, so Java can release the image; `7` and timeouts retain it.

Warnings (x64 `context + 88`, x86 `context + 28`):

- bit `1` (x64): early unwind-table registration failed.
- bit `2` (x64): static TLS was requested but `LdrpHandleTlsData` was
  unavailable or returned a failure NTSTATUS.
- bit `4` (x86): the image has a TLS directory, which this path ignores.

Warnings are reported on stderr and do not fail the mapping.

## Context layouts

Both contexts are explicit on both sides (`static_assert` in each loader).

x64, 104 bytes:

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

x86, 36 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | image base |
| 4 | 4 | `LoadLibraryA` |
| 8 | 4 | `GetProcAddress` |
| 12 | 4 | status |
| 16 | 4 | Win32 error |
| 20 | 4 | `GetLastError` |
| 24 | 4 | `DllMain` reason |
| 28 | 4 | warning bits |
| 32 | 4 | `DllMain` reserved |

## Standalone converter

The compiler/converter lives in the library's separate `tools` source set and
is excluded from the runtime JAR. Run it through Gradle from the project root:

```powershell
.\gradlew.bat :library:converter --args='extract library/build/native/loader64.exe build/loader64.bin'
.\gradlew.bat :library:converter --args='bytes build/loader64.bin'
```

Compile loader changes through Gradle so compiler/linker flags remain consistent.
Generated native products and byte arrays stay under the module's `build/`.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 T1xel.
See [third-party notices](THIRD_PARTY_NOTICES.md) for the upstream design
reference and runtime dependency notices. License files are included in the
published JARs and CLI distributions.
