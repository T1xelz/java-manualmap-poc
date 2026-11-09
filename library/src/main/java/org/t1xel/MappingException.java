package org.t1xel;

import java.io.IOException;

/** A mapping failure with a stable category and optional native error details. */
public final class MappingException extends IOException {
    public enum Kind {
        VALIDATION, UNSUPPORTED_PLATFORM, IO, NATIVE_CALL, LOADER, WAIT
    }

    private final Kind kind;
    private final String operation;
    private final Integer nativeError;

    public MappingException(Kind kind, String message, Throwable cause) {
        this(kind, message, cause, null, null);
    }

    public MappingException(Kind kind, String message, Throwable cause, String operation, Integer nativeError) {
        super(message, cause);
        this.kind = kind;
        this.operation = operation;
        this.nativeError = nativeError;
    }

    public Kind kind() {
        return kind;
    }

    /** Native operation name, or null when the failure is not a Win32 API call. */
    public String operation() {
        return operation;
    }

    /** Win32 error code, or null when no native error is available. */
    public Integer nativeError() {
        return nativeError;
    }
}
