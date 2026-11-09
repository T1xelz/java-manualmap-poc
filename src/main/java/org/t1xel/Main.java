package org.t1xel;

import java.nio.file.Path;
import java.util.Locale;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            usage();
            System.exit(2);
        }
        try {
            int pid = Integer.parseInt(args[0]);
            if (pid <= 0) {
                throw new IllegalArgumentException("PID must be positive");
            }
            MappingOptions.Builder options = MappingOptions.builder();
            for (int i = 2; i < args.length; i++) {
                switch (args[i]) {
                    case "--keep-header" -> options.clearHeader(false);
                    case "--keep-sections" -> options.clearNonNeededSections(false);
                    case "--no-protections" -> options.adjustProtections(false);
                    case "--no-seh" -> options.sehSupport(false);
                    case "--no-tls" -> options.tlsSupport(false);
                    case "--reason" -> options.dllMainReason(reason(argument(args, ++i, "--reason")));
                    case "--reserved" -> options.dllMainReserved(reserved(argument(args, ++i, "--reserved")));
                    default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            long address = new ManualMapper().map(pid, Path.of(args[1]), options.build());
            System.out.printf("Mapped image at 0x%016X%n", address);
        } catch (Exception exception) {
            System.err.println(exception.getMessage());
            System.exit(1);
        }
    }

    private static String argument(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException(option + " requires a value");
        }
        return args[index];
    }

    private static int reason(String value) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "detach", "process-detach" -> MappingOptions.DLL_PROCESS_DETACH;
            case "attach", "process-attach" -> MappingOptions.DLL_PROCESS_ATTACH;
            case "thread-attach" -> MappingOptions.DLL_THREAD_ATTACH;
            case "thread-detach" -> MappingOptions.DLL_THREAD_DETACH;
            default -> Integer.parseInt(value);
        };
    }

    private static long reserved(String value) {
        return value.startsWith("0x") || value.startsWith("0X") ? Long.parseUnsignedLong(value.substring(2), 16)
                : Long.parseLong(value);
    }

    private static void usage() {
        System.err.println("""
                Usage: ManualMap <process-id> <dll-path> [options]
                  PE32+ (AMD64) DLL -> native AMD64 process
                  PE32 (x86) DLL    -> WOW64 (x86) process
                  --reason <0..3|attach|detach|thread-attach|thread-detach>
                  --reserved <decimal|0xhex>
                  --keep-header        retain PE headers
                  --keep-sections      retain .rsrc/.reloc/.pdata
                  --no-protections     leave the image RWX
                  --no-seh             skip unwind-table registration and EH stubs (x64 only)
                  --no-tls             skip static TLS provisioning (x64 only)""");
    }
}
