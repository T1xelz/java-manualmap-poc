package org.t1xel;

/**
 * Mapping behaviour exposed to callers. Defaults match the reference
 * implementation: headers and discardable sections are cleared after a
 * successful load, section protections are restored, SEH/unwind tables are
 * registered, static TLS is provisioned through ntdll, and DllMain is called
 * with DLL_PROCESS_ATTACH and a null reserved pointer.
 */
public final class MappingOptions {
    public static final int DLL_PROCESS_DETACH = 0;
    public static final int DLL_PROCESS_ATTACH = 1;
    public static final int DLL_THREAD_ATTACH = 2;
    public static final int DLL_THREAD_DETACH = 3;

    private final boolean clearHeader;
    private final boolean clearNonNeededSections;
    private final boolean adjustProtections;
    private final boolean sehSupport;
    private final boolean tlsSupport;
    private final int dllMainReason;
    private final long dllMainReserved;

    public MappingOptions(boolean clearHeader, boolean clearNonNeededSections, boolean adjustProtections,
            boolean sehSupport, boolean tlsSupport, int dllMainReason, long dllMainReserved) {
        if (dllMainReason < DLL_PROCESS_DETACH || dllMainReason > DLL_THREAD_DETACH) {
            throw new IllegalArgumentException("DllMain reason must be 0..3");
        }
        this.clearHeader = clearHeader;
        this.clearNonNeededSections = clearNonNeededSections;
        this.adjustProtections = adjustProtections;
        this.sehSupport = sehSupport;
        this.tlsSupport = tlsSupport;
        this.dllMainReason = dllMainReason;
        this.dllMainReserved = dllMainReserved;
    }

    public boolean clearHeader() {
        return clearHeader;
    }

    public boolean clearNonNeededSections() {
        return clearNonNeededSections;
    }

    public boolean adjustProtections() {
        return adjustProtections;
    }

    public boolean sehSupport() {
        return sehSupport;
    }

    public boolean tlsSupport() {
        return tlsSupport;
    }

    public int dllMainReason() {
        return dllMainReason;
    }

    public long dllMainReserved() {
        return dllMainReserved;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof MappingOptions)) {
            return false;
        }
        MappingOptions that = (MappingOptions) other;
        return clearHeader == that.clearHeader
                && clearNonNeededSections == that.clearNonNeededSections
                && adjustProtections == that.adjustProtections
                && sehSupport == that.sehSupport
                && tlsSupport == that.tlsSupport
                && dllMainReason == that.dllMainReason
                && dllMainReserved == that.dllMainReserved;
    }

    @Override
    public int hashCode() {
        int result = 0;
        result = 31 * result + Boolean.hashCode(clearHeader);
        result = 31 * result + Boolean.hashCode(clearNonNeededSections);
        result = 31 * result + Boolean.hashCode(adjustProtections);
        result = 31 * result + Boolean.hashCode(sehSupport);
        result = 31 * result + Boolean.hashCode(tlsSupport);
        result = 31 * result + dllMainReason;
        result = 31 * result + Long.hashCode(dllMainReserved);
        return result;
    }

    @Override
    public String toString() {
        return "MappingOptions[clearHeader=" + clearHeader + ", clearNonNeededSections=" + clearNonNeededSections
                + ", adjustProtections=" + adjustProtections + ", sehSupport=" + sehSupport
                + ", tlsSupport=" + tlsSupport + ", dllMainReason=" + dllMainReason
                + ", dllMainReserved=" + dllMainReserved + "]";
    }

    public static MappingOptions defaults() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private boolean clearHeader = true;
        private boolean clearNonNeededSections = true;
        private boolean adjustProtections = true;
        private boolean sehSupport = true;
        private boolean tlsSupport = true;
        private int dllMainReason = DLL_PROCESS_ATTACH;
        private long dllMainReserved;

        public Builder clearHeader(boolean value) {
            clearHeader = value;
            return this;
        }

        public Builder clearNonNeededSections(boolean value) {
            clearNonNeededSections = value;
            return this;
        }

        public Builder adjustProtections(boolean value) {
            adjustProtections = value;
            return this;
        }

        public Builder sehSupport(boolean value) {
            sehSupport = value;
            return this;
        }

        public Builder tlsSupport(boolean value) {
            tlsSupport = value;
            return this;
        }

        public Builder dllMainReason(int value) {
            dllMainReason = value;
            return this;
        }

        public Builder dllMainReserved(long value) {
            dllMainReserved = value;
            return this;
        }

        public MappingOptions build() {
            return new MappingOptions(clearHeader, clearNonNeededSections, adjustProtections, sehSupport, tlsSupport,
                    dllMainReason, dllMainReserved);
        }
    }
}
