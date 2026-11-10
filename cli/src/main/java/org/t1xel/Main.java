package org.t1xel;

import java.nio.file.Paths;
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
                    case "--keep-header":
                        options.clearHeader(false);
                        break;
                    case "--keep-sections":
                        options.clearNonNeededSections(false);
                        break;
                    case "--no-protections":
                        options.adjustProtections(false);
                        break;
                    case "--no-seh":
                        options.sehSupport(false);
                        break;
                    case "--no-tls":
                        options.tlsSupport(false);
                        break;
                    case "--reason":
                        options.dllMainReason(reason(argument(args, ++i, "--reason")));
                        break;
                    case "--reserved":
                        options.dllMainReserved(reserved(argument(args, ++i, "--reserved")));
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown option: " + args[i]);
                }
            }
            MappingResult result = new ManualMapper().mapResult(pid, Paths.get(args[1]), options.build());
            for (String warning : result.warnings()) {
                System.err.println(warning);
            }
            System.out.printf("Mapped image at 0x%016X%n", result.address());
        } catch (MappingException exception) {
            System.err.println(exception.kind() + ": " + exception.getMessage());
            System.exit(1);
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
        switch (value.toLowerCase(Locale.ROOT)) {
            case "detach":
            case "process-detach":
                return MappingOptions.DLL_PROCESS_DETACH;
            case "attach":
            case "process-attach":
                return MappingOptions.DLL_PROCESS_ATTACH;
            case "thread-attach":
                return MappingOptions.DLL_THREAD_ATTACH;
            case "thread-detach":
                return MappingOptions.DLL_THREAD_DETACH;
            default:
                return Integer.parseInt(value);
        }
    }

    private static long reserved(String value) {
        return value.startsWith("0x") || value.startsWith("0X") ? Long.parseUnsignedLong(value.substring(2), 16)
                : Long.parseLong(value);
    }

    private static void usage() {
        System.err.println("Usage: ManualMap <process-id> <dll-path> [options]\n"
                + "  PE32+ (AMD64) DLL -> native AMD64 process\n"
                + "  PE32 (x86) DLL    -> WOW64 (x86) process\n"
                + "  --reason <0..3|attach|detach|thread-attach|thread-detach>\n"
                + "  --reserved <decimal|0xhex>\n"
                + "  --keep-header        retain PE headers\n"
                + "  --keep-sections      retain .rsrc/.reloc/.pdata\n"
                + "  --no-protections     leave the image RWX\n"
                + "  --no-seh             skip unwind-table registration and EH stubs (x64 only)\n"
                + "  --no-tls             skip static TLS provisioning (x64 only)");
    }
}
