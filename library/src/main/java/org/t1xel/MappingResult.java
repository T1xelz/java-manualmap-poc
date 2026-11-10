package org.t1xel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Successful image address and diagnostics, including cleanup warnings. */
public final class MappingResult {
    private final long address;
    private final List<String> warnings;

    public MappingResult(long address, List<String> warnings) {
        Objects.requireNonNull(warnings, "warnings");
        for (String warning : warnings) {
            Objects.requireNonNull(warning, "warning");
        }
        this.address = address;
        this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
    }

    public long address() {
        return address;
    }

    public List<String> warnings() {
        return warnings;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MappingResult)) {
            return false;
        }
        MappingResult that = (MappingResult) other;
        return address == that.address
                && Objects.equals(warnings, that.warnings);
    }

    @Override
    public int hashCode() {
        int result = 0;
        result = 31 * result + Long.hashCode(address);
        result = 31 * result + Objects.hashCode(warnings);
        return result;
    }

    @Override
    public String toString() {
        return "MappingResult[address=" + address + ", warnings=" + warnings + "]";
    }

}
