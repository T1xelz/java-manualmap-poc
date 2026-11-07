package org.t1xel;

import org.junit.jupiter.api.Test;
import org.t1xel.tools.ShellcodeTool;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeImageTest {
    static byte[] minimalDll() {
        byte[] bytes = new byte[1024];
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort(0, (short) 0x5A4D);
        b.putInt(0x3C, 0x80);
        b.putInt(0x80, 0x4550);
        b.putShort(0x84, (short) 0x8664);
        b.putShort(0x86, (short) 1);
        b.putShort(0x94, (short) 240);
        b.putShort(0x96, (short) 0x2000);
        b.putShort(0x98, (short) 0x20B);
        b.putInt(0x98 + 16, 0x1000);
        b.putLong(0x98 + 24, 0x180000000L);
        b.putInt(0x98 + 32, 0x1000);
        b.putInt(0x98 + 56, 0x3000);
        b.putInt(0x98 + 60, 0x200);
        b.putInt(0x98 + 108, 16);
        int section = 0x188;
        b.position(section);
        b.put(new byte[]{'.', 't', 'e', 'x', 't', 0, 0, 0});
        b.putInt(section + 8, 0x300);
        b.putInt(section + 12, 0x1000);
        b.putInt(section + 16, 0x200);
        b.putInt(section + 20, 0x200);
        b.putInt(section + 36, 0x60000020);
        bytes[0x200] = (byte) 0xC3;
        return bytes;
    }

    @Test
    void mapsRawDataAndZeroFillsVirtualTail() {
        PeImage image = new PeImage(minimalDll());
        image.validateDll();
        assertEquals(0xC3, image.mappedBytes()[0x1000] & 255);
        assertEquals(0, image.mappedBytes()[0x1250]);
        assertEquals(0x180000000L, image.preferredBase);
    }

    @Test
    void rejectsTruncationAndOverflow() {
        byte[] bytes = minimalDll();
        for (int length = 0; length < bytes.length; length++) {
            byte[] truncated = Arrays.copyOf(bytes, length);
            assertThrows(IllegalArgumentException.class, () -> new PeImage(truncated));
        }
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(0x3C, Integer.MAX_VALUE);
        assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes));
    }

    @Test
    void rejectsUnsupportedDllFeatures() {
        byte[] bytes = minimalDll();
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0x98 + 112 + 13 * 8, 0x1000);
        b.putInt(0x98 + 116 + 13 * 8, 32);
        assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes).validateDll());
        b.putInt(0x98 + 116 + 13 * 8, 0);
        b.putInt(0x98 + 112 + 9 * 8, 0x1000);
        b.putInt(0x98 + 116 + 9 * 8, 40);
        b.putLong(0x200, 0x180001100L);
        b.putLong(0x208, 0x180001108L);
        assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes).validateDll());
    }

    @Test
    void randomInputsFailWithValidationErrors() {
        Random random = new Random(42);
        for (int i = 0; i < 1000; i++) {
            byte[] bytes = new byte[random.nextInt(2048)];
            random.nextBytes(bytes);
            assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes));
        }
    }

    @Test
    void converterPreservesUnsignedBytes() {
        String text = ShellcodeTool.javaBytes(new byte[]{0, 0x7F, (byte) 0x80, (byte) 0xFF});
        assertTrue(text.contains("(byte) 0x80, (byte) 0xFF"));
        assertTrue(text.endsWith("\n};\n"));
    }

    @Test
    void rejectsInvalidImportAndRelocationTables() {
        byte[] bytes = minimalDll();
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0x98 + 112 + 1 * 8, 0x1000);
        b.putInt(0x98 + 116 + 1 * 8, 20);
        b.putInt(0x20C, 0x4000);
        assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes).validateDll());
        b.putInt(0x98 + 116 + 1 * 8, 0);
        b.putInt(0x98 + 112 + 5 * 8, 0x1000);
        b.putInt(0x98 + 116 + 5 * 8, 8);
        b.putInt(0x200, 0x1000);
        b.putInt(0x204, 0);
        assertThrows(IllegalArgumentException.class, () -> new PeImage(bytes).validateDll());
    }

    @Test
    void extractedJumpTargetsLinkedEntryPoint() throws Exception {
        byte[] code;
        try (var input = PeImageTest.class.getResourceAsStream("/loader.bin")) {
            assertTrue(input != null);
            code = input.readAllBytes();
        }
        PeImage linked = new PeImage(Files.readAllBytes(Path.of("build/native/loader.exe")));
        int text = linked.sections().stream().filter(section -> section.name().equals(".text")).findFirst().orElseThrow().rva();
        assertEquals(0xE9, code[0] & 255);
        assertEquals(linked.entryRva - text, ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN).getInt(1));
    }
}
