# ManualMap

Java library and CLI for mapping Windows DLLs into AMD64 or x86 (WOW64) processes.
Accepts a DLL path or raw DLL file bytes (`byte[]`).

## Build

Requires Windows x64, an AMD64 JDK 21+, MSVC x86/x64 build tools and a Windows SDK.
Gradle uses a JDK 21 toolchain. MSVC is discovered automatically; override it with
`MANUALMAP_VCVARS64` / `MANUALMAP_VCVARS32` if needed.

```powershell
.\gradlew.bat build
.\gradlew.bat :library:publishToMavenLocal
```

The library JAR is `library/build/libs/manualmap-1.0.jar`.
In your application's `build.gradle.kts`:

```kotlin
repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("org.t1xel:manualmap:1.0")
}
```

## Library example

```java
import org.t1xel.ManualMapper;
import org.t1xel.MappingException;
import org.t1xel.MappingResult;

public final class Example {
    public static void mapDll(int pid, byte[] dllBytes) {
        try {
            ManualMapper mapper = new ManualMapper();
            MappingResult result = mapper.mapResult(pid, dllBytes);

            System.out.printf("Mapped at 0x%016X%n", result.address());
            result.warnings().forEach(System.err::println);
        } catch (MappingException error) {
            System.err.println(error.kind() + ": " + error.getMessage());
            if (error.nativeError() != null) {
                System.err.println(error.operation() + ": Win32=" + error.nativeError());
            }
        }
    }
}
```

For a path, import `java.nio.file.Path` and call
`mapper.mapResult(pid, Path.of("C:/samples/example.dll"))` instead.
Both input types also accept `MappingOptions` as a third argument.
Use `map(...)` if you only need the address, or `mapResult(...)` for the address
and warnings. The byte-array overload does not write a temporary DLL or modify
the input; do not modify the array during the call. The library does not print
to the console or exit the JVM.

A complete runnable example with both modes is in
[examples/LibraryExample.java](examples/LibraryExample.java).

## CLI and tests

```powershell
.\gradlew.bat :cli:run --args='1234 C:/samples/example.dll'
.\gradlew.bat :library:test
.\gradlew.bat :library:integrationTest
```

Integration tests launch disposable hosts and cover both path and byte-array inputs.
The source modules are `library/` and `cli/`; native sources, build tools and
tests live in separate source sets inside `library/`.

## Limits

The JVM must be AMD64. DLL and target architectures must match. Static TLS and
SEH/C++ exception support are x64-only. There is no unload API. On timeout or
certain initialization failures, remote allocations are retained because DLL code
may still be running.

## License

[MIT](LICENSE), copyright (c) 2026 T1xel.
Design reference: [TheCruZ/Simple-Manual-Map-Injector](https://github.com/TheCruZ/Simple-Manual-Map-Injector).
See [third-party notices](THIRD_PARTY_NOTICES.md).
