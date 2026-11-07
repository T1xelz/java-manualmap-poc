package org.t1xel;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfSystemProperty(named = "manualmap.integration", matches = "true")
class MappingIntegrationTest {
    @Test
    void mapsFixtureAtRelocatedBaseAndCallsDllMain() throws Exception {
        Path dll = Path.of("build/native/fixture.dll").toAbsolutePath();
        PeImage pe = new PeImage(Files.readAllBytes(dll));
        Process host = new ProcessBuilder(Path.of("build/native/host.exe").toAbsolutePath().toString()).start();
        Pointer process = null;
        try {
            Thread.sleep(200);
            assertTrue(host.isAlive());
            WinApi api = WinApi.INSTANCE;
            process = api.OpenProcess(0x043A, false, (int) host.pid());
            assertNotNull(process);
            Pointer reserved = api.VirtualAllocEx(process, Pointer.createConstant(pe.preferredBase), pe.imageSize, 0x3000, 4);
            assertNotNull(reserved, "Reserve preferred base to exercise DIR64 relocations");
            long image = new ManualMapper().map((int) host.pid(), dll);
            assertNotEquals(pe.preferredBase, image);
            // DllMain sets a field through an absolute relocated pointer and calls imported APIs.
            int stateRva = exportedRva(pe, "MmAttached");
            byte[] bytes = new byte[4];
            PointerByReference count = new PointerByReference();
            assertTrue(api.ReadProcessMemory(process, Pointer.createConstant(image + stateRva), bytes, 4, count));
            assertEquals(4, Pointer.nativeValue(count.getValue()));
            assertEquals((int) host.pid(), ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt());
            assertTrue(host.waitFor(10, TimeUnit.SECONDS), "Fixture host should observe its named event");
            assertEquals(0, host.exitValue());
        } finally {
            if (process != null) {
                WinApi.INSTANCE.CloseHandle(process);
            }
            host.destroyForcibly();
            host.waitFor(5, TimeUnit.SECONDS);
        }
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
