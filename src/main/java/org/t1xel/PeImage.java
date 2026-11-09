package org.t1xel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Bounded PE32/PE32+ reader shared by the mapper and native-code extractor. */
public final class PeImage {
    public enum Arch {
        X86(0x14C, 0x10B, 96, 4),
        X64(0x8664, 0x20B, 112, 8);

        private final int machine;
        private final int magic;
        private final int directoryOffset;
        private final int pointerSize;

        Arch(int machine, int magic, int directoryOffset, int pointerSize) {
            this.machine = machine;
            this.magic = magic;
            this.directoryOffset = directoryOffset;
            this.pointerSize = pointerSize;
        }
    }

    public record Section(String name, int rva, int virtualSize, int rawOffset, int rawSize, int characteristics) {
        public int mappedSize() {
            return Math.max(virtualSize, rawSize);
        }
    }

    private final byte[] file;
    private final ByteBuffer bytes;
    private final Arch arch;
    private final int optional;
    private final int directoryOffset;
    private final int directories;
    private final List<Section> sections = new ArrayList<>();
    public final int machine;
    public final int imageSize;
    public final int headerSize;
    public final int entryRva;
    public final long preferredBase;
    public final boolean dll;

    public PeImage(byte[] file) {
        this.file = file.clone();
        bytes = ByteBuffer.wrap(this.file).order(ByteOrder.LITTLE_ENDIAN);
        require(file.length >= 64 && u16(0) == 0x5A4D, "Missing DOS header");
        int nt = positive(i32(0x3C), "PE offset");
        range(nt, 24, file.length);
        require(i32(nt) == 0x4550, "Missing PE signature");
        machine = u16(nt + 4);
        arch = switch (machine) {
            case 0x8664 -> Arch.X64;
            case 0x14C -> Arch.X86;
            default -> throw new IllegalArgumentException("Unsupported PE machine 0x" + Integer.toHexString(machine));
        };
        int count = u16(nt + 6);
        require(count > 0 && count <= 96, "Invalid section count");
        int optionalSize = u16(nt + 20);
        optional = nt + 24;
        range(optional, optionalSize, file.length);
        require(optionalSize >= arch.directoryOffset && u16(optional) == arch.magic,
                "Optional header does not match the PE machine");
        directoryOffset = optional + arch.directoryOffset;
        directories = positive(i32(arch == Arch.X64 ? optional + 108 : optional + 92), "Directory count");
        require(directories <= 16 && arch.directoryOffset + (long) directories * 8 <= optionalSize,
                "Invalid directory table");
        dll = (u16(nt + 22) & 0x2000) != 0;
        imageSize = positive(i32(optional + 56), "Image size");
        require(imageSize > 0 && imageSize <= 512 * 1024 * 1024, "Image exceeds 512 MiB limit");
        headerSize = positive(i32(optional + 60), "Header size");
        range(0, headerSize, file.length);
        range(0, headerSize, imageSize);
        entryRva = positive(i32(optional + 16), "Entry point");
        range(entryRva, 1, imageSize);
        preferredBase = arch == Arch.X64 ? bytes.getLong(optional + 24) : Integer.toUnsignedLong(i32(optional + 28));
        int alignment = i32(optional + 32);
        require(alignment >= 4096 && (alignment & (alignment - 1)) == 0, "Section alignment must be at least one page");
        require(imageSize % alignment == 0 && headerSize > 0 && headerSize <= alignment, "Invalid image/header alignment");
        int table = optional + optionalSize;
        range(table, count * 40, headerSize);
        for (int i = 0; i < count; i++) {
            int at = table + i * 40;
            String name = new String(this.file, at, 8, StandardCharsets.US_ASCII).replace("\0", "");
            Section section = new Section(name, positive(i32(at + 12), "Section RVA"),
                    positive(i32(at + 8), "Virtual size"), positive(i32(at + 20), "Raw offset"),
                    positive(i32(at + 16), "Raw size"), i32(at + 36));
            require(section.rva() >= headerSize && section.rva() % alignment == 0, "Invalid section alignment");
            range(section.rva(), section.mappedSize(), imageSize);
            if (section.rawSize() > 0) {
                range(section.rawOffset(), section.rawSize(), file.length);
            }
            for (Section previous : sections) {
                require((long) section.rva() + section.mappedSize() <= previous.rva()
                        || (long) previous.rva() + previous.mappedSize() <= section.rva(), "Overlapping sections");
            }
            sections.add(section);
        }
        for (int i = 0; i < directories; i++) {
            if (i != 4) {
                range(directoryRva(i), directorySize(i), imageSize);
                require(directorySize(i) == 0 || directoryRva(i) != 0, "Nonempty directory has zero RVA");
            }
        }
    }

    public Arch arch() {
        return arch;
    }

    public boolean is64() {
        return arch == Arch.X64;
    }

    public int pointerSize() {
        return arch.pointerSize;
    }

    public List<Section> sections() {
        return List.copyOf(sections);
    }

    public int directoryRva(int index) {
        return index < directories ? positive(i32(directoryOffset + index * 8), "Directory RVA") : 0;
    }

    public int directorySize(int index) {
        return index < directories ? positive(i32(directoryOffset + index * 8 + 4), "Directory size") : 0;
    }

    public byte[] mappedBytes() {
        byte[] image = new byte[imageSize];
        System.arraycopy(file, 0, image, 0, headerSize);
        for (Section section : sections) {
            if (section.rawSize() != 0) {
                System.arraycopy(file, section.rawOffset(), image, section.rva(), section.rawSize());
            }
        }
        return image;
    }

    public void validateDll() {
        require(dll, "Expected a DLL");
        require(directories == 16, "DLL must contain the full PE data-directory table");
        require(directorySize(13) == 0 && directorySize(14) == 0, "Delay imports and CLR images are unsupported");
        require(entryRva == 0 || sections.stream().anyMatch(section -> (section.characteristics() & 0x20000000) != 0
                && entryRva >= section.rva() && entryRva < (long) section.rva() + section.mappedSize()),
                "Entry point must belong to an executable section");
        ByteBuffer image = ByteBuffer.wrap(mappedBytes()).order(ByteOrder.LITTLE_ENDIAN);
        validateImports(image);
        validateRelocations(image);
        if (arch == Arch.X64) {
            validateExceptions(image);
        }
        validateTls(image);
    }

    /** Validates the AMD64 runtime-function table (x86 uses SEH frames, not .pdata). */
    private void validateExceptions(ByteBuffer image) {
        int exceptions = directoryRva(3);
        require(directorySize(3) % 12 == 0, "Invalid runtime-function table size");
        int previousEnd = 0;
        for (int offset = 0; offset < directorySize(3); offset += 12) {
            int begin = image.getInt(exceptions + offset);
            int end = image.getInt(exceptions + offset + 4);
            require(begin >= previousEnd && end > begin && end <= imageSize, "Invalid runtime-function range");
            range(image.getInt(exceptions + offset + 8), 4, imageSize);
            previousEnd = end;
        }
    }

    /** Validates the static TLS template, index cell, and callback array. */
    private void validateTls(ByteBuffer image) {
        int size = directorySize(9);
        if (size == 0) {
            return;
        }
        if (arch == Arch.X64) {
            validateTls64(image, size);
        } else {
            validateTls32(image, size);
        }
    }

    private void validateTls64(ByteBuffer image, int size) {
        require(size >= 40, "Truncated TLS directory");
        int tls = directoryRva(9);
        range(tls, 40, imageSize);
        long start = image.getLong(tls);
        long end = image.getLong(tls + 8);
        long index = image.getLong(tls + 16);
        long callbacks = image.getLong(tls + 24);
        long zeroFill = Integer.toUnsignedLong(image.getInt(tls + 32));
        long templateSize = 0;
        if (start == 0) {
            require(end == 0, "TLS raw-data end without start");
        } else {
            int startRva = preferredRva(start);
            int endRva = preferredRva(end, true);
            require(endRva >= startRva, "TLS raw-data range is inverted");
            templateSize = endRva - startRva;
        }
        require(templateSize + zeroFill <= 16L * 1024 * 1024, "TLS block exceeds 16 MiB limit");
        require(index != 0, "TLS index address is missing");
        int indexRva = preferredRva(index);
        range(indexRva, 4, imageSize);
        require(indexRva % 4 == 0, "TLS index is misaligned");
        require(inSection(indexRva, 0x80000000), "TLS index must be writable");
        if (callbacks != 0) {
            int at = preferredRva(callbacks);
            require(at % 8 == 0, "TLS callback array is misaligned");
            for (int count = 0; ; count++) {
                require(count < 4096, "TLS callback array is unterminated");
                range(at, 8, imageSize);
                long callback = image.getLong(at);
                if (callback == 0) {
                    break;
                }
                require(inSection(preferredRva(callback), 0x20000000),
                        "TLS callback must belong to an executable section");
                at += 8;
            }
        }
    }

    private void validateTls32(ByteBuffer image, int size) {
        require(size >= 24, "Truncated TLS directory");
        int tls = directoryRva(9);
        range(tls, 24, imageSize);
        long start = Integer.toUnsignedLong(image.getInt(tls));
        long end = Integer.toUnsignedLong(image.getInt(tls + 4));
        long index = Integer.toUnsignedLong(image.getInt(tls + 8));
        long callbacks = Integer.toUnsignedLong(image.getInt(tls + 12));
        long zeroFill = Integer.toUnsignedLong(image.getInt(tls + 16));
        long templateSize = 0;
        if (start == 0) {
            require(end == 0, "TLS raw-data end without start");
        } else {
            int startRva = preferredRva(start);
            int endRva = preferredRva(end, true);
            require(endRva >= startRva, "TLS raw-data range is inverted");
            templateSize = endRva - startRva;
        }
        require(templateSize + zeroFill <= 16L * 1024 * 1024, "TLS block exceeds 16 MiB limit");
        require(index != 0, "TLS index address is missing");
        int indexRva = preferredRva(index);
        range(indexRva, 4, imageSize);
        require(indexRva % 4 == 0, "TLS index is misaligned");
        require(inSection(indexRva, 0x80000000), "TLS index must be writable");
        if (callbacks != 0) {
            int at = preferredRva(callbacks);
            require(at % 4 == 0, "TLS callback array is misaligned");
            for (int count = 0; ; count++) {
                require(count < 4096, "TLS callback array is unterminated");
                range(at, 4, imageSize);
                long callback = Integer.toUnsignedLong(image.getInt(at));
                if (callback == 0) {
                    break;
                }
                require(inSection(preferredRva(callback), 0x20000000),
                        "TLS callback must belong to an executable section");
                at += 4;
            }
        }
    }

    private boolean inSection(int rva, int characteristic) {
        return sections.stream().anyMatch(section -> (section.characteristics() & characteristic) != 0
                && rva >= section.rva() && rva < (long) section.rva() + section.mappedSize());
    }

    private int preferredRva(long address) {
        return preferredRva(address, false);
    }

    private int preferredRva(long address, boolean allowEnd) {
        long rva = address - preferredBase;
        require(rva >= 0 && (allowEnd ? rva <= imageSize : rva < imageSize), "TLS address outside image");
        return (int) rva;
    }

    private void validateImports(ByteBuffer image) {
        if (directorySize(1) == 0) {
            return;
        }
        int thunkSize = arch.pointerSize;
        int directory = directoryRva(1);
        for (int offset = 0; offset + 20 <= directorySize(1); offset += 20) {
            int descriptor = directory + offset;
            int name = image.getInt(descriptor + 12);
            if (name == 0) {
                return;
            }
            validateString(image, name);
            int destination = image.getInt(descriptor + 16);
            int source = image.getInt(descriptor);
            if (source == 0) {
                source = destination;
            }
            require(source != 0 && destination != 0, "Missing import thunk table");
            for (int i = 0; ; i += thunkSize) {
                range(source, i + thunkSize, imageSize);
                range(destination, i + thunkSize, imageSize);
                long thunk = arch == Arch.X64 ? image.getLong(source + i) : Integer.toUnsignedLong(image.getInt(source + i));
                if (thunk == 0) {
                    break;
                }
                boolean ordinal = arch == Arch.X64 ? thunk < 0 : (thunk & 0x80000000L) != 0;
                if (!ordinal) {
                    require(thunk <= imageSize - 3, "Import name outside image");
                    validateString(image, (int) thunk + 2);
                }
            }
        }
        throw new IllegalArgumentException("Import directory lacks a terminator");
    }

    private void validateString(ByteBuffer image, int rva) {
        range(rva, 1, imageSize);
        int limit = (int) Math.min((long) rva + 32768, imageSize);
        for (int at = rva; at < limit; at++) {
            if (image.get(at) == 0) {
                return;
            }
        }
        throw new IllegalArgumentException("Unterminated import string");
    }

    private void validateRelocations(ByteBuffer image) {
        int directory = directoryRva(5);
        int expectedType = arch == Arch.X64 ? 10 : 3;
        int width = arch.pointerSize;
        for (int offset = 0; offset < directorySize(5);) {
            require(directorySize(5) - offset >= 8, "Truncated relocation block");
            int page = image.getInt(directory + offset);
            int size = image.getInt(directory + offset + 4);
            require(size >= 8 && size <= directorySize(5) - offset && size % 2 == 0, "Invalid relocation block");
            for (int at = offset + 8; at < offset + size; at += 2) {
                int entry = Short.toUnsignedInt(image.getShort(directory + at));
                int type = entry >>> 12;
                if (type != 0) {
                    require(type == expectedType, arch == Arch.X64
                            ? "Only DIR64 and ABSOLUTE relocations are supported"
                            : "Only HIGHLOW and ABSOLUTE relocations are supported");
                    long rva = (long) page + (entry & 0xFFF);
                    require(rva >= 0 && rva + width <= imageSize, "Relocation outside image");
                }
            }
            offset += size;
        }
    }

    private int i32(int at) {
        return bytes.getInt(at);
    }

    private int u16(int at) {
        return Short.toUnsignedInt(bytes.getShort(at));
    }

    private static int positive(int value, String name) {
        require(value >= 0, name + " exceeds supported range");
        return value;
    }

    public static void range(int offset, int length, int limit) {
        require(offset >= 0 && length >= 0 && (long) offset + length <= limit, "PE range outside image/file");
    }

    public static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
