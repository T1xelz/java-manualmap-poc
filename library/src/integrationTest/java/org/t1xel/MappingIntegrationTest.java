package org.t1xel;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfSystemProperty(named = "manualmap.integration", matches = "true")
class MappingIntegrationTest {
    private static final int MAGIC = 0x4D4D5445;
    // 27 checks in every fixture, 28 for /EHa (catch(...) also catches AV).
    private static final int MIN_CHECKS = 27;

    @ParameterizedTest
    @ValueSource(strings = {"ehsc_md", "eha_md", "ehsc_mt", "eha_mt", "ehac_mt"})
    void mapsFixtureWithTlsAndExceptions(String mode) throws Exception {
        Path dll = Paths.get("build/native/fixture_" + mode + ".dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host.exe")) {
            long image = new ManualMapper().map(host.pid(), dll);
            assertFixture(host, pe, image, MappingOptions.DLL_PROCESS_ATTACH, 0);
            assertHostExit(host);
        }
    }

    @Test
    void mapsFixtureFromBytesWithoutChangingInput() throws Exception {
        byte[] dll = Files.readAllBytes(Paths.get("build/native/fixture_ehsc_md.dll"));
        byte[] original = dll.clone();
        PeImage pe = new PeImage(dll);
        try (NativeTestHost host = NativeTestHost.launch("build/native/host.exe")) {
            MappingResult result = new ManualMapper().mapResult(host.pid(), dll, MappingOptions.defaults());
            assertFixture(host, pe, result.address(), MappingOptions.DLL_PROCESS_ATTACH, 0);
            assertArrayEquals(original, dll);
            assertHostExit(host);
        }
    }

    @Test
    void mapsRelocatedMdFixtureAndClearsSections() throws Exception {
        Path dll = Paths.get("build/native/fixture_ehsc_md.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host.exe")) {
            Pointer reserved = WinApi.INSTANCE.VirtualAllocEx(host.process, Pointer.createConstant(pe.preferredBase),
                    pe.imageSize, 0x3000, 4);
            assertNotNull(reserved, "Reserve preferred base to exercise DIR64 relocations");
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
    void honoursConfiguredDllMainParametersAndMappingFlags() throws Exception {
        Path dll = Paths.get("build/native/fixture_ehsc_md.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        try (NativeTestHost host = NativeTestHost.launch("build/native/host.exe")) {
            MappingOptions options = MappingOptions.builder()
                    .dllMainReason(MappingOptions.DLL_THREAD_ATTACH)
                    .dllMainReserved(0x1234)
                    .clearHeader(false)
                    .build();
            long image = new ManualMapper().map(host.pid(), dll, options);
            MmResults results = results(host.process, pe, image);
            assertEquals(MAGIC, results.magic());
            assertEquals(MappingOptions.DLL_THREAD_ATTACH, results.reason());
            assertEquals(0x1234, results.reserved());
            byte[] header = read(host.process, image, 2);
            assertEquals('M', header[0]);
            assertEquals('Z', header[1]);
            assertHostExit(host);
        }
    }

    private static void assertFixture(NativeTestHost host, PeImage pe, long image, int reason, int reserved) {
        int stateRva = exportedRva(pe, "MmAttached");
        byte[] bytes = read(host.process, image + stateRva, 4);
        assertEquals(host.pid(), ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt());
        MmResults results = results(host.process, pe, image);
        assertEquals(MAGIC, results.magic());
        assertEquals(reason, results.reason());
        assertEquals(reserved, results.reserved());
        assertEquals(1, results.tlsCallbacks());
        assertEquals(0x1235, results.tlsMain());
        assertEquals(0x1234, results.tlsWorker(), "new thread must receive the TLS template copy");
        assertEquals(1, results.tlsIsolated(), "thread_local must be isolated per thread");
        assertEquals(0x1235, results.tlsMainAfter());
        assertEquals(0, results.threadAttach(), "manually mapped modules receive no DLL_THREAD_ATTACH callback");
        assertEquals(0, results.fail(), "every fixture check should pass, failMask=0x"
                + Integer.toHexString(results.failMask()));
        assertTrue(results.pass() >= MIN_CHECKS, "expected at least " + MIN_CHECKS + " checks, got " + results.pass());
    }

    private static MmResults results(Pointer process, PeImage pe, long image) {
        byte[] bytes = read(process, image + exportedRva(pe, "MmResultsData"), 48);
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        return new MmResults(b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt(),
                b.getInt(), b.getInt(), b.getInt(), b.getInt(), b.getInt());
    }

    private static final class MmResults {
        private final int magic;
        private final int pass;
        private final int fail;
        private final int reason;
        private final int reserved;
        private final int tlsCallbacks;
        private final int tlsMain;
        private final int tlsMainAfter;
        private final int tlsWorker;
        private final int tlsIsolated;
        private final int threadAttach;
        private final int failMask;

        private MmResults(int magic, int pass, int fail, int reason, int reserved, int tlsCallbacks, int tlsMain,
                int tlsMainAfter, int tlsWorker, int tlsIsolated, int threadAttach, int failMask) {
            this.magic = magic;
            this.pass = pass;
            this.fail = fail;
            this.reason = reason;
            this.reserved = reserved;
            this.tlsCallbacks = tlsCallbacks;
            this.tlsMain = tlsMain;
            this.tlsMainAfter = tlsMainAfter;
            this.tlsWorker = tlsWorker;
            this.tlsIsolated = tlsIsolated;
            this.threadAttach = threadAttach;
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

        public int tlsCallbacks() {
            return tlsCallbacks;
        }

        public int tlsMain() {
            return tlsMain;
        }

        public int tlsMainAfter() {
            return tlsMainAfter;
        }

        public int tlsWorker() {
            return tlsWorker;
        }

        public int tlsIsolated() {
            return tlsIsolated;
        }

        public int threadAttach() {
            return threadAttach;
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
