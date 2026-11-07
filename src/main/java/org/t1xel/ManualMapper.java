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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class ManualMapper {
    private static final int PAGE_READWRITE = 0x04;
    private static final int PAGE_EXECUTE_READ = 0x20;
    private static final int PAGE_EXECUTE_READWRITE = 0x40;
    private static final int MEM_RELEASE = 0x8000;

    public long map(int pid, Path dll) throws IOException {
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
            image = api.VirtualAllocEx(process, Pointer.createConstant(pe.preferredBase), pe.imageSize, 0x3000, PAGE_READWRITE);
            if (image == null) {
                PeImage.require(pe.directorySize(5) != 0, "Preferred base occupied and DLL has no relocations");
                image = allocate(process, pe.imageSize);
            }
            write(process, image, pe.mappedBytes());
            protect(process, image, pe.imageSize, PAGE_EXECUTE_READWRITE);
            check(api.FlushInstructionCache(process, image, pe.imageSize), "FlushInstructionCache(image)");
            code = allocate(process, stub.length);
            write(process, code, stub);
            protect(process, code, stub.length, PAGE_EXECUTE_READ);
            check(api.FlushInstructionCache(process, code, stub.length), "FlushInstructionCache(loader)");
            context = allocate(process, 56);
            try (Memory data = new Memory(56)) {
                data.clear();
                data.setPointer(0, image);
                data.setLong(8, remoteFunction("kernel32", "LoadLibraryA", modules));
                data.setLong(16, remoteFunction("kernel32", "GetProcAddress", modules));
                data.setLong(24, remoteFunction("kernel32", "RtlAddFunctionTable", modules));
                data.setLong(32, remoteFunction("kernel32", "RtlDeleteFunctionTable", modules));
                data.setLong(48, remoteFunction("kernel32", "GetLastError", modules));
                write(process, context, data.getByteArray(0, 56));
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
            int status = (result[0] & 255) | ((result[1] & 255) << 8)
                    | ((result[2] & 255) << 16) | (result[3] << 24);
            int error = (result[4] & 255) | ((result[5] & 255) << 8)
                    | ((result[6] & 255) << 16) | (result[7] << 24);
            if (status != 1 || exit.getValue() != 0) {
                // Only pre-initialization failures can be rolled back without DLL side effects.
                retainImage = status < 2 || status > 6;
                throw new IOException("Loader status=" + status + ", exit=0x"
                        + Integer.toHexString(exit.getValue()) + ", Win32=" + error
                        + (retainImage ? "; image retained at 0x" + Long.toHexString(Pointer.nativeValue(image)) : ""));
            }
            finalizeProtections(process, image, pe);
            mapped = true;
            return Pointer.nativeValue(image);
        } finally {
            if (!started || stopped) {
                free(process, code);
                free(process, context);
                if (!mapped && !retainImage) {
                    free(process, image);
                }
            }
            if (thread != null) {
                api.CloseHandle(thread);
            }
            api.CloseHandle(process);
        }
    }

    private static void finalizeProtections(Pointer process, Pointer image, PeImage pe) {
        protect(process, image, pe.headerSize, 0x02);
        int cursor = (pe.headerSize + 4095) & ~4095;
        for (PeImage.Section section : pe.sections().stream().sorted(Comparator.comparingInt(PeImage.Section::rva)).toList()) {
            if (section.mappedSize() == 0) {
                continue;
            }
            if (section.rva() > cursor) {
                protect(process, image.share(cursor), section.rva() - cursor, 0x01);
            }
            boolean execute = (section.characteristics() & 0x20000000) != 0;
            boolean read = (section.characteristics() & 0x40000000) != 0;
            boolean write = (section.characteristics() & 0x80000000) != 0;
            int protection = execute ? (write ? 0x40 : (read ? 0x20 : 0x10)) : (write ? 0x04 : (read ? 0x02 : 0x01));
            protect(process, image.share(section.rva()), section.mappedSize(), protection);
            cursor = (section.rva() + section.mappedSize() + 4095) & ~4095;
        }
        if (cursor < pe.imageSize) {
            protect(process, image.share(cursor), pe.imageSize - cursor, 0x01);
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

    private static Pointer allocate(Pointer process, long size) {
        Pointer address = WinApi.INSTANCE.VirtualAllocEx(process, null, size, 0x3000, PAGE_READWRITE);
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
