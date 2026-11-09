package org.t1xel;

import java.util.List;

/** Successful image address and diagnostics, including cleanup warnings. */
public record MappingResult(long address, List<String> warnings) {
    public MappingResult {
        warnings = List.copyOf(warnings);
    }
}
