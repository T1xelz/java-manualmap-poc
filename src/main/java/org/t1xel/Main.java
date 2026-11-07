package org.t1xel;

import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: ManualMap <x64-process-id> <x64-dll-path>");
            System.exit(2);
        }
        try {
            int pid = Integer.parseInt(args[0]);
            if (pid <= 0) {
                throw new IllegalArgumentException("PID must be positive");
            }
            long address = new ManualMapper().map(pid, Path.of(args[1]));
            System.out.printf("Mapped image at 0x%016X%n", address);
        } catch (Exception exception) {
            System.err.println(exception.getMessage());
            System.exit(1);
        }
    }
}
