import org.t1xel.ManualMapper;
import org.t1xel.MappingException;
import org.t1xel.MappingOptions;
import org.t1xel.MappingResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class LibraryExample {
    private LibraryExample() {
    }

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3 || (args.length == 3 && !args[2].equals("--bytes"))) {
            System.err.println("Usage: LibraryExample <pid> <dll-path> [--bytes]");
            return;
        }

        try {
            int pid = Integer.parseInt(args[0]);
            Path path = Paths.get(args[1]);
            ManualMapper mapper = new ManualMapper();
            MappingOptions options = MappingOptions.defaults();

            MappingResult result;
            if (args.length == 3) {
                byte[] dll = Files.readAllBytes(path);
                result = mapper.mapResult(pid, dll, options);
            } else {
                result = mapper.mapResult(pid, path, options);
            }

            System.out.printf("Mapped at 0x%016X%n", result.address());
            result.warnings().forEach(System.err::println);
        } catch (MappingException error) {
            System.err.println(error.kind() + ": " + error.getMessage());
            if (error.nativeError() != null) {
                System.err.println(error.operation() + ": Win32=" + error.nativeError());
            }
        } catch (IOException | IllegalArgumentException error) {
            System.err.println(error.getMessage());
        }
    }
}
