package org.t1xel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MappingApiTest {
    @Test
    void validatesArgumentsBeforeAccessingNativeApi() {
        ManualMapper mapper = new ManualMapper();
        MappingException invalidPid = assertThrows(MappingException.class,
                () -> mapper.map(0, Path.of("missing.dll")));
        assertEquals(MappingException.Kind.VALIDATION, invalidPid.kind());
        assertInstanceOf(IllegalArgumentException.class, invalidPid.getCause());
        assertNull(invalidPid.nativeError());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class, () -> mapper.map(1, null)).kind());
        assertEquals(MappingException.Kind.VALIDATION,
                assertThrows(MappingException.class,
                        () -> mapper.map(1, Path.of("missing.dll"), null)).kind());
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
        List<String> warnings = new ArrayList<>(List.of("warning"));
        MappingResult result = new MappingResult(123, warnings);
        warnings.clear();
        assertEquals(123, result.address());
        assertEquals(List.of("warning"), result.warnings());
        assertThrows(UnsupportedOperationException.class, () -> result.warnings().clear());
    }
}
