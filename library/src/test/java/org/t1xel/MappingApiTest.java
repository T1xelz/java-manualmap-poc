package org.t1xel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MappingApiTest {
    @Test
    void immutableValuesRetainEqualityAndValidation() {
        MappingOptions defaults = MappingOptions.defaults();
        MappingOptions same = new MappingOptions(true, true, true, true, true, 1, 0);
        assertEquals(defaults, same);
        assertEquals(defaults.hashCode(), same.hashCode());
        assertNotEquals(defaults, MappingOptions.builder().dllMainReserved(42).build());
        assertThrows(IllegalArgumentException.class,
                () -> MappingOptions.builder().dllMainReason(4).build());

        MappingResult first = new MappingResult(123, Arrays.asList("warning"));
        MappingResult second = new MappingResult(123, Arrays.asList("warning"));
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals("MappingResult[address=123, warnings=[warning]]", first.toString());
        assertThrows(NullPointerException.class, () -> new MappingResult(0, null));
        assertThrows(NullPointerException.class, () -> new MappingResult(0, Arrays.asList((String) null)));
    }

    @Test
    void validatesArgumentsBeforeAccessingNativeApi() {
        ManualMapper mapper = new ManualMapper();
        MappingException invalidPid = assertThrows(MappingException.class,
                () -> mapper.map(0, Paths.get("missing.dll")));
        assertEquals(MappingException.Kind.VALIDATION, invalidPid.kind());
        assertInstanceOf(IllegalArgumentException.class, invalidPid.getCause());
        assertNull(invalidPid.nativeError());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class, () -> mapper.map(1, (Path) null)).kind());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class,
                        () -> mapper.map(1, Paths.get("missing.dll"), null)).kind());
    }

    @Test
    void rejectsMissingOrEmptyBytes() {
        ManualMapper mapper = new ManualMapper();
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class, () -> mapper.map(1, (byte[]) null)).kind());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class, () -> mapper.mapResult(1, new byte[0])).kind());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class,
                        () -> mapper.mapResult(1, new byte[]{1}, null)).kind());
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void rejectsMalformedBytesBeforeOpeningProcess() {
        MappingException error = assertThrows(MappingException.class,
                () -> new ManualMapper().mapResult(1, new byte[]{1, 2, 3}));
        assertEquals(MappingException.Kind.VALIDATION, error.kind());
        assertInstanceOf(IllegalArgumentException.class, error.getCause());
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void preservesFileErrorCause(@TempDir Path directory) {
        MappingException error = assertThrows(MappingException.class,
                () -> new ManualMapper().map(1, directory.resolve("missing.dll")));
        assertEquals(MappingException.Kind.IO, error.kind());
        assertInstanceOf(NoSuchFileException.class, error.getCause());
    }

    @Test
    void resultOwnsAnImmutableSnapshotOfWarnings() {
        List<String> warnings = new ArrayList<>(Arrays.asList("warning"));
        MappingResult result = new MappingResult(123, warnings);
        warnings.clear();
        assertEquals(123, result.address());
        assertEquals(Arrays.asList("warning"), result.warnings());
        assertThrows(UnsupportedOperationException.class, () -> result.warnings().clear());
    }
}
