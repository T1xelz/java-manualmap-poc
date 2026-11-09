package org.t1xel;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class ManualMapper {
    private static final int PAGE_NOACCESS = 0x01;
    private static final int PAGE_READONLY = 0x02;
    private static final int PAGE_READWRITE = 0x04;
    private static final int PAGE_EXECUTE = 0x10;
    private static final int PAGE_EXECUTE_READ = 0x20;
    private static final int PAGE_EXECUTE_READWRITE = 0x40;
    private static final int MEM_COMMIT_RESERVE = 0x3000;
    private static final int MEM_RELEASE = 0x8000;
    private static final int PAGE_SIZE = 0x1000;
    private static final int CONTEXT_SIZE = 104;
    private static final int FLAG_SEH = 1;
    private static final int FLAG_TLS = 2;
    private static final int MAX_REMOTE_SECTION = 64 * 1024 * 1024;
    private static final String LDRP_TLS_PATTERN = "44 8D ? 09 [5-24] B2 01 48 8B ? 30 E8";

    public long map(int pid, Path dll) throws IOException {
        return map(pid, dll, MappingOptions.defaults());
    }

    public long map(int pid, Path dll, MappingOptions options) throws IOException {
        PeImage.require(Platform.isWindows() && Native.POINTER_SIZE == 8 && Platform.isIntel(),
                "Use an AMD64 Windows JVM");
        PeImage.require(Files.size(dll) <= 512L * 1024 * 1024, "DLL exceeds 512 MiB limit");
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        pe.validateDll();
        byte[] stub;
        try (InputStream resource = ManualMapper.class.getResourceAsStream("/loader.bin")) {
            if (resource == null) {
                throw new IOException("Missing loader.bin; build with gradlew build first");
            }
            stub = resource.readAllBytes();
        }
        WinApi api = WinApi.INSTANCE;
        Pointer process = api.OpenProcess(0x043A, false, pid);
        check(process != null, "OpenProcess");
        Pointer image = null;
        Pointer code = null;
        Pointer context = null;
        Pointer throwStub = null;
        Pointer pcTrampoline = null;
        Pointer thread = null;
        boolean started = false;
        boolean stopped = false;
        boolean mapped = false;
        boolean retainImage = false;
        try {
            ShortByReference machine = new ShortByReference();
            ShortByReference nativeMachine = new ShortByReference();
            check(api.IsWow64Process2(process, machine, nativeMachine), "IsWow64Process2");
            PeImage.require(machine.getValue() == 0 && Short.toUnsignedInt(nativeMachine.getValue()) == 0x8664,
                    "Target must be native AMD64");
            Map<String, Long> modules = modules(pid);
            image = api.VirtualAllocEx(process, Pointer.createConstant(pe.preferredBase), pe.imageSize,
                    MEM_COMMIT_RESERVE, PAGE_READWRITE);
            if (image == null) {
                PeImage.require(pe.directorySize(5) != 0, "Preferred base occupied and DLL has no relocations");
                image = allocate(process, pe.imageSize, PAGE_READWRITE);
            }
            write(process, image, pe.mappedBytes());
            protect(process, image, pe.imageSize, PAGE_EXECUTE_READWRITE);
            check(api.FlushInstructionCache(process, image, pe.imageSize), "FlushInstructionCache(image)");
            code = allocate(process, stub.length, PAGE_READWRITE);
            write(process, code, stub);
            protect(process, code, stub.length, PAGE_EXECUTE_READ);
            check(api.FlushInstructionCache(process, code, stub.length), "FlushInstructionCache(loader)");

            long loadLibrary = remoteFunction("kernel32", "LoadLibraryA", modules);
            long getProcAddress = remoteFunction("kernel32", "GetProcAddress", modules);
            long addFunctionTable = remoteFunction("kernel32", "RtlAddFunctionTable", modules);
            long deleteFunctionTable = remoteFunction("kernel32", "RtlDeleteFunctionTable", modules);
            long getLastError = remoteFunction("kernel32", "GetLastError", modules);

            if (options.sehSupport()) {
                long raiseException = remoteFunction("kernel32", "RaiseException", modules);
                long rtlPcToFileHeader = remoteFunction("ntdll", "RtlPcToFileHeader", modules);
                throwStub = createPage(process, throwStub(Pointer.nativeValue(image), raiseException));
                pcTrampoline = createPage(process, rtlPcTrampoline(Pointer.nativeValue(image),
                        Pointer.nativeValue(image) + pe.imageSize, rtlPcToFileHeader));
            }
            long ldrpHandleTlsData = 0;
            if (options.tlsSupport() && pe.directorySize(9) != 0) {
                ldrpHandleTlsData = findLdrpHandleTlsData(process, modules);
                if (ldrpHandleTlsData == 0) {
                    System.err.println("Loader warning: LdrpHandleTlsData not found; static TLS unavailable");
                }
            }

            context = allocate(process, CONTEXT_SIZE, PAGE_READWRITE);
            try (Memory data = new Memory(CONTEXT_SIZE)) {
                data.clear();
                data.setPointer(0, image);
                data.setLong(8, loadLibrary);
                data.setLong(16, getProcAddress);
                data.setLong(24, addFunctionTable);
                data.setLong(32, deleteFunctionTable);
                data.setInt(40, 0);
                data.setInt(44, 0);
                data.setLong(48, getLastError);
                data.setLong(56, ldrpHandleTlsData);
                data.setLong(64, throwStub == null ? 0 : Pointer.nativeValue(throwStub));
                data.setLong(72, pcTrampoline == null ? 0 : Pointer.nativeValue(pcTrampoline));
                data.setInt(80, options.dllMainReason());
                data.setInt(84, (options.sehSupport() ? FLAG_SEH : 0) | (options.tlsSupport() ? FLAG_TLS : 0));
                data.setInt(88, 0);
                data.setLong(96, options.dllMainReserved());
                write(process, context, data.getByteArray(0, CONTEXT_SIZE));
            }
            thread = api.CreateRemoteThread(process, null, 0, code, context, 0, null);
            check(thread != null, "CreateRemoteThread");
            started = true;
            int wait = api.WaitForSingleObject(thread, 30_000);
            if (wait != 0) {
                throw new IOException("Loader wait returned 0x" + Integer.toHexString(wait)
                        + "; remote allocations retained because the thread may still be running: image=0x"
                        + Long.toHexString(Pointer.nativeValue(image)) + ", code=0x"
                        + Long.toHexString(Pointer.nativeValue(code)) + ", context=0x"
                        + Long.toHexString(Pointer.nativeValue(context)));
            }
            stopped = true;
            // A fault may have left registered unwind tables or DLL-owned threads behind.
            retainImage = true;
            IntByReference exit = new IntByReference();
            check(api.GetExitCodeThread(thread, exit), "GetExitCodeThread");
            byte[] result = read(process, context.share(40), 8);
            int status = littleInt(result, 0);
            int error = littleInt(result, 4);
            int warning = littleInt(read(process, context.share(88), 4), 0);
            if (status != 1 || exit.getValue() != 0) {
                // Only pre-initialization failures can be rolled back without DLL side effects.
                retainImage = status < 2 || status > 5;
                throw new IOException("Loader status=" + status + ", exit=0x"
                        + Integer.toHexString(exit.getValue()) + ", Win32=" + error
                        + (retainImage ? "; image retained at 0x" + Long.toHexString(Pointer.nativeValue(image)) : ""));
            }
            reportWarning(warning);
            if (options.clearHeader()) {
                clearHeader(process, image, pe);
            }
            if (options.clearNonNeededSections()) {
                clearSections(process, image, pe, options.sehSupport());
            }
            if (options.adjustProtections()) {
                finalizeProtections(process, image, pe);
            }
            mapped = true;
            return Pointer.nativeValue(image);
        } finally {
            if (!started || stopped) {
                free(process, code);
                free(process, context);
                if (!mapped && !retainImage) {
                    free(process, throwStub);
                    free(process, pcTrampoline);
                    free(process, image);
                }
            }
            if (thread != null) {
                api.CloseHandle(thread);
            }
            api.CloseHandle(process);
        }
    }

    private static void reportWarning(int warning) {
        if ((warning & 1) != 0) {
            System.err.println("Loader warning: early unwind-table registration failed; C++ exceptions may not unwind");
        }
        if ((warning & 2) != 0) {
            System.err.println("Loader warning: static TLS requested but LdrpHandleTlsData was unavailable");
        }
    }

    private static int littleInt(byte[] bytes, int offset) {
        return (bytes[offset] & 255) | ((bytes[offset + 1] & 255) << 8)
                | ((bytes[offset + 2] & 255) << 16) | (bytes[offset + 3] << 24);
    }

    private static void clearHeader(Pointer process, Pointer image, PeImage pe) {
        int size = pe.sections().stream().mapToInt(PeImage.Section::rva).min().orElse(PAGE_SIZE);
        zero(process, image, Math.min(Math.max(size, PAGE_SIZE), pe.imageSize));
    }

    private static void clearSections(Pointer process, Pointer image, PeImage pe, boolean sehSupport) {
        for (PeImage.Section section : pe.sections()) {
            if (section.mappedSize() == 0) {
                continue;
            }
            boolean discard = section.name().equals(".rsrc") || section.name().equals(".reloc")
                    || (!sehSupport && section.name().equals(".pdata"));
            if (discard) {
                zero(process, image.share(section.rva()), section.mappedSize());
            }
        }
    }

    private static void zero(Pointer process, Pointer address, int size) {
        int done = 0;
        while (done < size) {
            int chunk = Math.min(1024 * 1024, size - done);
            write(process, address.share(done), new byte[chunk]);
            done += chunk;
        }
    }

    private static byte[] throwStub(long imageBase, long raiseException) {
        byte[] stub = {
                0x48, (byte) 0x83, (byte) 0xEC, 0x48,
                (byte) 0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, (byte) 0x93, 0x19,
                (byte) 0xC7, 0x44, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00,
                0x48, (byte) 0x89, 0x4C, 0x24, 0x28,
                0x48, (byte) 0x89, 0x54, 0x24, 0x30,
                0x48, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                0x48, (byte) 0x89, 0x44, 0x24, 0x38,
                (byte) 0xB9, 0x63, 0x73, 0x6D, (byte) 0xE0,
                (byte) 0xBA, 0x01, 0x00, 0x00, 0x00,
                0x41, (byte) 0xB8, 0x04, 0x00, 0x00, 0x00,
                0x4C, (byte) 0x8D, 0x4C, 0x24, 0x20,
                0x48, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                (byte) 0xFF, (byte) 0xD0,
                (byte) 0xCC
        };
        ByteBuffer.wrap(stub).order(ByteOrder.LITTLE_ENDIAN).putLong(32, imageBase).putLong(68, raiseException);
        byte[] blob = new byte[0xB0];
        System.arraycopy(stub, 0, blob, 0, stub.length);
        // UNWIND_INFO: version 1, prolog 4 bytes, one UWOP_ALLOC_SMALL(0x48) code.
        blob[0x80] = 0x01;
        blob[0x81] = 0x04;
        blob[0x82] = 0x01;
        blob[0x83] = 0x00;
        blob[0x84] = 0x04;
        blob[0x85] = (byte) 0x82;
        ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0xA0, 0).putInt(0xA4, stub.length).putInt(0xA8, 0x80);
        return blob;
    }

    private static byte[] rtlPcTrampoline(long imageBase, long imageEnd, long original) {
        byte[] code = {
                0x48, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                0x48, 0x39, (byte) 0xC1,
                0x72, 0x18,
                0x49, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                0x4C, 0x39, (byte) 0xC1,
                0x73, 0x09,
                0x48, (byte) 0x85, (byte) 0xD2,
                0x74, 0x03,
                0x48, (byte) 0x89, 0x02,
                (byte) 0xC3,
                0x48, (byte) 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
                (byte) 0xFF, (byte) 0xE0
        };
        ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(2, imageBase).putLong(0x11, imageEnd).putLong(0x29, original);
        return code;
    }

    private static Pointer createPage(Pointer process, byte[] bytes) {
        Pointer page = allocate(process, PAGE_SIZE, PAGE_EXECUTE_READWRITE);
        write(process, page, bytes);
        protect(process, page, PAGE_SIZE, PAGE_EXECUTE_READ);
        check(WinApi.INSTANCE.FlushInstructionCache(process, page, PAGE_SIZE), "FlushInstructionCache(page)");
        return page;
    }

    private static long findLdrpHandleTlsData(Pointer process, Map<String, Long> modules) {
        Long ntdll = modules.get("ntdll.dll");
        if (ntdll == null) {
            return 0;
        }
        try {
            SectionBytes text = readSection(process, ntdll, ".text");
            if (text == null) {
                return 0;
            }
            int hit = PatternScanner.scan(text.bytes, 0, text.bytes.length, LDRP_TLS_PATTERN, 0);
            if (hit < 0) {
                return 0;
            }
            int start = Math.max(0, hit - 0x400);
            int padding = PatternScanner.scanBackward(text.bytes, start, hit - start, "CC CC CC");
            if (padding < 0) {
                return 0;
            }
            int at = padding;
            while (at < text.bytes.length && (text.bytes[at] & 255) == 0xCC) {
                at++;
            }
            return at < text.bytes.length ? ntdll + text.rva + at : 0;
        } catch (RuntimeException exception) {
            System.err.println("Loader warning: TLS pattern scan failed: " + exception.getMessage());
            return 0;
        }
    }

    private record SectionBytes(int rva, byte[] bytes) {
    }

    private static SectionBytes readSection(Pointer process, long moduleBase, String name) {
        byte[] header = read(process, Pointer.createConstant(moduleBase), PAGE_SIZE);
        ByteBuffer bytes = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        PeImage.require(bytes.getShort(0) == (short) 0x5A4D && bytes.getInt(0x3C) > 0, "Invalid remote module header");
        int nt = bytes.getInt(0x3C);
        PeImage.range(nt, 24, header.length);
        PeImage.require(bytes.getInt(nt) == 0x4550, "Invalid remote PE signature");
        int count = Short.toUnsignedInt(bytes.getShort(nt + 6));
        int optionalSize = Short.toUnsignedInt(bytes.getShort(nt + 20));
        int table = nt + 24 + optionalSize;
        PeImage.require(count > 0 && count <= 96, "Invalid remote section count");
        PeImage.range(table, count * 40, header.length);
        for (int i = 0; i < count; i++) {
            int at = table + i * 40;
            String candidate = new String(header, at, 8, StandardCharsets.US_ASCII).replace("\0", "");
            if (!candidate.equals(name)) {
                continue;
            }
            int virtualSize = bytes.getInt(at + 8);
            int rva = bytes.getInt(at + 12);
            int rawSize = bytes.getInt(at + 16);
            int size = Math.max(virtualSize, rawSize);
            PeImage.require(size > 0 && size <= MAX_REMOTE_SECTION, "Remote section exceeds scan limit");
            return new SectionBytes(rva, readLarge(process, moduleBase + rva, size));
        }
        return null;
    }

    private static byte[] readLarge(Pointer process, long address, int size) {
        byte[] result = new byte[size];
        int done = 0;
        while (done < size) {
            int chunk = Math.min(1024 * 1024, size - done);
            byte[] part = read(process, Pointer.createConstant(address + done), chunk);
            System.arraycopy(part, 0, result, done, chunk);
            done += chunk;
        }
        return result;
    }

    private static void finalizeProtections(Pointer process, Pointer image, PeImage pe) {
        protect(process, image, pe.headerSize, PAGE_READONLY);
        int cursor = (pe.headerSize + 4095) & ~4095;
        for (PeImage.Section section : pe.sections().stream().sorted(Comparator.comparingInt(PeImage.Section::rva)).toList()) {
            if (section.mappedSize() == 0) {
                continue;
            }
            if (section.rva() > cursor) {
                protect(process, image.share(cursor), section.rva() - cursor, PAGE_NOACCESS);
            }
            boolean execute = (section.characteristics() & 0x20000000) != 0;
            boolean read = (section.characteristics() & 0x40000000) != 0;
            boolean write = (section.characteristics() & 0x80000000) != 0;
            int protection = execute ? (write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE))
                    : (write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS));
            protect(process, image.share(section.rva()), section.mappedSize(), protection);
            cursor = (section.rva() + section.mappedSize() + 4095) & ~4095;
        }
        if (cursor < pe.imageSize) {
            protect(process, image.share(cursor), pe.imageSize - cursor, PAGE_NOACCESS);
        }
        check(WinApi.INSTANCE.FlushInstructionCache(process, image, pe.imageSize), "FlushInstructionCache(final)");
    }

    private static Map<String, Long> modules(int pid) {
        WinApi api = WinApi.INSTANCE;
        Pointer snapshot = api.CreateToolhelp32Snapshot(0x08, pid);
        check(snapshot != null && Pointer.nativeValue(snapshot) != -1L, "CreateToolhelp32Snapshot");
        try {
            Map<String, Long> result = new HashMap<>();
            WinApi.ModuleEntry entry = new WinApi.ModuleEntry();
            check(api.Module32FirstW(snapshot, entry), "Module32FirstW");
            do {
                result.put(Native.toString(entry.name).toLowerCase(Locale.ROOT), Pointer.nativeValue(entry.base));
            } while (api.Module32NextW(snapshot, entry));
            check(Native.getLastError() == 18, "Module32NextW");
            return result;
        } finally {
            api.CloseHandle(snapshot);
        }
    }

    private static long remoteFunction(String library, String name, Map<String, Long> modules) {
        Pointer function = NativeLibrary.getInstance(library).getFunction(name);
        PointerByReference owner = new PointerByReference();
        check(WinApi.INSTANCE.GetModuleHandleExW(0x06, function, owner), "GetModuleHandleExW");
        char[] path = new char[32768];
        int length = WinApi.INSTANCE.GetModuleFileNameW(owner.getValue(), path, path.length);
        check(length > 0 && length < path.length, "GetModuleFileNameW");
        String module = Path.of(new String(path, 0, length)).getFileName().toString().toLowerCase(Locale.ROOT);
        Long base = modules.get(module);
        PeImage.require(base != null, "Target is missing API owner " + module);
        // Resolve forwarded exports locally, then translate the actual owning module's RVA.
        return base + Pointer.nativeValue(function) - Pointer.nativeValue(owner.getValue());
    }

    private static Pointer allocate(Pointer process, long size, int protection) {
        Pointer address = WinApi.INSTANCE.VirtualAllocEx(process, null, size, MEM_COMMIT_RESERVE, protection);
        check(address != null, "VirtualAllocEx");
        return address;
    }

    private static void write(Pointer process, Pointer address, byte[] bytes) {
        PointerByReference written = new PointerByReference();
        check(WinApi.INSTANCE.WriteProcessMemory(process, address, bytes, bytes.length, written), "WriteProcessMemory");
        PeImage.require(Pointer.nativeValue(written.getValue()) == bytes.length, "Short remote write");
    }

    private static byte[] read(Pointer process, Pointer address, int size) {
        byte[] bytes = new byte[size];
        PointerByReference read = new PointerByReference();
        check(WinApi.INSTANCE.ReadProcessMemory(process, address, bytes, size, read), "ReadProcessMemory");
        PeImage.require(Pointer.nativeValue(read.getValue()) == size, "Short remote read");
        return bytes;
    }

    private static void protect(Pointer process, Pointer address, long size, int protection) {
        check(WinApi.INSTANCE.VirtualProtectEx(process, address, size, protection, new IntByReference()), "VirtualProtectEx");
    }

    private static void free(Pointer process, Pointer address) {
        if (address != null && !WinApi.INSTANCE.VirtualFreeEx(process, address, 0, MEM_RELEASE)) {
            System.err.println("VirtualFreeEx failed: Win32=" + Native.getLastError());
        }
    }

    private static void check(boolean success, String operation) {
        if (!success) {
            throw new IllegalStateException(operation + " failed: Win32=" + Native.getLastError());
        }
    }
}
