package org.t1xel;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfSystemProperty(named = "manualmap.integration", matches = "true")
class MappingIntegrationX86Test {
    private static final int MAGIC = 0x4D4D5445;

    @Test
    void mapsX86FixtureWithImportsAndRelocations() throws Exception {
        Path dll = Paths.get("build/native/fixture32.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host32.exe")) {
            long image = new ManualMapper().map(host.pid(), dll);
            assertFixture(host, pe, image, MappingOptions.DLL_PROCESS_ATTACH, 0);
            assertHostExit(host);
        }
    }

    @Test
    void mapsX86FixtureFromBytes() throws Exception {
        byte[] dll = Files.readAllBytes(Paths.get("build/native/fixture32.dll"));
        PeImage pe = new PeImage(dll);
        try (NativeTestHost host = NativeTestHost.launch("build/native/host32.exe")) {
            long image = new ManualMapper().map(host.pid(), dll);
            assertFixture(host, pe, image, MappingOptions.DLL_PROCESS_ATTACH, 0);
            assertHostExit(host);
        }
    }

    @Test
    void mapsRelocatedX86FixtureAndClearsSections() throws Exception {
        Path dll = Paths.get("build/native/fixture32.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host32.exe")) {
            Pointer reserved = WinApi.INSTANCE.VirtualAllocEx(host.process, Pointer.createConstant(pe.preferredBase),
                    pe.imageSize, 0x3000, 4);
            assertNotNull(reserved, "Reserve preferred base to exercise HIGHLOW relocations");
            long image = new ManualMapper().map(host.pid(), dll);
            assertNotEquals(pe.preferredBase, image);
            assertFixture(host, pe, image, MappingOptions.DLL_PROCESS_ATTACH, 0);
            assertTrue(read(host.process, image, 2)[0] == 0 && read(host.process, image, 2)[1] == 0,
                    "PE header should be cleared");
            assertSectionCleared(host, pe, image, ".reloc");
            assertHostExit(host);
        }
    }

    @Test
    void honoursConfiguredDllMainParameters() throws Exception {
        Path dll = Paths.get("build/native/fixture32.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host32.exe")) {
            MappingOptions options = MappingOptions.builder()
                    .dllMainReason(MappingOptions.DLL_THREAD_ATTACH)
                    .dllMainReserved(0x1234)
                    .clearHeader(false)
                    .build();
            long image = new ManualMapper().map(host.pid(), dll, options);
            Results results = results(host.process, pe, image);
            assertEquals(MAGIC, results.magic());
            assertEquals(MappingOptions.DLL_THREAD_ATTACH, results.reason());
            assertEquals(0x1234, results.reserved());
            byte[] header = read(host.process, image, 2);
            assertEquals('M', header[0]);
            assertEquals('Z', header[1]);
            assertHostExit(host);
        }
    }

    @Test
    void rejectsX86ImageForNativeAmd64Target() throws Exception {
        Path dll = Paths.get("build/native/fixture32.dll").toAbsolutePath();
        try (NativeTestHost host = NativeTestHost.launch("build/native/host.exe")) {
            MappingException error = assertThrows(MappingException.class,
                    () -> new ManualMapper().map(host.pid(), dll));
            assertTrue(error.getMessage().contains("WOW64"), error.getMessage());
        }
    }

    @Test
    void rejectsAmd64ImageForWow64Target() throws Exception {
        Path dll = Paths.get("build/native/fixture_ehsc_md.dll").toAbsolutePath();
        try (NativeTestHost host = NativeTestHost.launch("build/native/host32.exe")) {
            MappingException error = assertThrows(MappingException.class,
                    () -> new ManualMapper().map(host.pid(), dll));
            assertTrue(error.getMessage().contains("AMD64"), error.getMessage());
        }
    }

    private static void assertFixture(NativeTestHost host, PeImage pe, long image, int reason, int reserved) {
        int attachedRva = exportedRva(pe, "MmAttached");
        assertEquals(host.pid(), littleInt(read(host.process, image + attachedRva, 4), 0));
        int pointerRva = exportedRva(pe, "MmAttachedPointer");
        assertEquals(image + attachedRva, Integer.toUnsignedLong(littleInt(read(host.process, image + pointerRva, 4), 0)));
        Results results = results(host.process, pe, image);
        assertEquals(MAGIC, results.magic());
        assertEquals(reason, results.reason());
        assertEquals(reserved, results.reserved());
        assertEquals(1, results.relocOk());
        assertEquals(1, results.importOk());
        assertEquals(1, results.moduleOk());
        assertEquals(0, results.fail(), "every fixture check should pass, failMask=0x"
                + Integer.toHexString(results.failMask()));
        assertTrue(results.pass() >= 3, "expected at least 3 checks, got " + results.pass());
    }

    private static Results results(Pointer process, PeImage pe, long image) {
        byte[] bytes = read(process, image + exportedRva(pe, "MmResultsData"), 36);
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        return new Results(b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(),
                b.getInt(), b.getInt());
    }

    private static final class Results {
        private final int magic;
        private final int pass;
        private final int fail;
        private final int reason;
        private final int reserved;
        private final int relocOk;
        private final int importOk;
        private final int moduleOk;
        private final int failMask;

        private Results(int magic, int pass, int fail, int reason, int reserved, int relocOk, int importOk, int moduleOk, int failMask) {
            this.magic = magic;
            this.pass = pass;
            this.fail = fail;
            this.reason = reason;
            this.reserved = reserved;
            this.relocOk = relocOk;
            this.importOk = importOk;
            this.moduleOk = moduleOk;
            this.failMask = failMask;
        }

        public int magic() {
            return magic;
        }

        public int pass() {
            return pass;
        }

        public int fail() {
            return fail;
        }

        public int reason() {
            return reason;
        }

        public int reserved() {
            return reserved;
        }

        public int relocOk() {
            return relocOk;
        }

        public int importOk() {
            return importOk;
        }

        public int moduleOk() {
            return moduleOk;
        }

        public int failMask() {
            return failMask;
        }
    }

    private static void assertSectionCleared(NativeTestHost host, PeImage pe, long image, String name) {
        pe.sections().stream().filter(section -> section.name().equals(name)).findFirst().ifPresent(section -> {
            byte[] bytes = read(host.process, image + section.rva(), Math.min(4, section.mappedSize()));
            for (byte value : bytes) {
                assertEquals(0, value, name + " should be cleared");
            }
        });
    }

    private static void assertHostExit(NativeTestHost host) throws Exception {
        host.assertSuccessfulExit();
    }

    private static byte[] read(Pointer process, long address, int size) {
        byte[] bytes = new byte[size];
        PointerByReference count = new PointerByReference();
        assertTrue(WinApi.INSTANCE.ReadProcessMemory(process, Pointer.createConstant(address), bytes, size, count));
        assertEquals(size, Pointer.nativeValue(count.getValue()));
        return bytes;
    }

    private static int littleInt(byte[] bytes, int offset) {
        return (bytes[offset] & 255) | ((bytes[offset + 1] & 255) << 8)
                | ((bytes[offset + 2] & 255) << 16) | (bytes[offset + 3] << 24);
    }

    private static int exportedRva(PeImage pe, String name) {
        ByteBuffer b = ByteBuffer.wrap(pe.mappedBytes()).order(ByteOrder.LITTLE_ENDIAN);
        int directory = pe.directoryRva(0);
        int names = b.getInt(directory + 32);
        int ordinals = b.getInt(directory + 36);
        int functions = b.getInt(directory + 28);
        for (int i = 0; i < b.getInt(directory + 24); i++) {
            int at = b.getInt(names + i * 4);
            StringBuilder candidate = new StringBuilder();
            while (b.get(at) != 0) {
                candidate.append((char) (b.get(at++) & 255));
            }
            if (candidate.toString().equals(name)) {
                return b.getInt(functions + Short.toUnsignedInt(b.getShort(ordinals + i * 2)) * 4);
            }
        }
        throw new AssertionError("Missing fixture export " + name);
    }

}
