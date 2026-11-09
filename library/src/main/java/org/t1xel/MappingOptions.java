package org.t1xel;

/**
 * Mapping behaviour exposed to callers. Defaults match the reference
 * implementation: headers and discardable sections are cleared after a
 * successful load, section protections are restored, SEH/unwind tables are
 * registered, static TLS is provisioned through ntdll, and DllMain is called
 * with DLL_PROCESS_ATTACH and a null reserved pointer.
 */
public record MappingOptions(boolean clearHeader, boolean clearNonNeededSections, boolean adjustProtections,
        boolean sehSupport, boolean tlsSupport, int dllMainReason, long dllMainReserved) {
    public static final int DLL_PROCESS_DETACH = 0;
    public static final int DLL_PROCESS_ATTACH = 1;
    public static final int DLL_THREAD_ATTACH = 2;
    public static final int DLL_THREAD_DETACH = 3;

    public MappingOptions {
        if (dllMainReason < DLL_PROCESS_DETACH || dllMainReason > DLL_THREAD_DETACH) {
            throw new IllegalArgumentException("DllMain reason must be 0..3");
        }
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
