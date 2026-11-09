package org.t1xel.tools;

import org.t1xel.PeImage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/** MSVC driver and PE .text-to-binary/Java-bytes converter, without native helper tools. */
public final class ShellcodeTool {
    private ShellcodeTool() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && (args[0].equals("build") || args[0].equals("fixtures"))) {
            Path root = Path.of(args[1]).toAbsolutePath();
            Path output = root.resolve("build/native");
            Files.createDirectories(output);
            if (args[0].equals("build")) {
                compile(root, output, "loader.cpp", "loader", ".exe",
                        "/GS- /GR- /EHs-c- /O1 /Oi /Gs9999999 /guard:cf- /Zl",
                        "/ENTRY:ManualMapShellcode /NODEFAULTLIB /SUBSYSTEM:CONSOLE /FIXED:NO /DYNAMICBASE:NO /OPT:NOICF /OPT:NOREF /MERGE:.rdata=.text");
                extract(output.resolve("loader.exe"), root.resolve("build/generated-shellcode/loader.bin"));
            } else {
                // Same source across every EH/CRT combination the reference
                // test matrix covers (x64 only).
                record Fixture(String name, String eh, String crt, String define) {
                }
                for (Fixture fixture : List.of(
                        new Fixture("ehsc_md", "/EHsc", "/MD", "EH_MODE_EHSC"),
                        new Fixture("eha_md", "/EHa", "/MD", "EH_MODE_EHA"),
                        new Fixture("ehsc_mt", "/EHsc", "/MT", "EH_MODE_EHSC"),
                        new Fixture("eha_mt", "/EHa", "/MT", "EH_MODE_EHA"),
                        new Fixture("ehac_mt", "/EHac", "/MT", "EH_MODE_EHAC"))) {
                    compile(root, output, "fixture.cpp", "fixture_" + fixture.name(), ".dll",
                            fixture.eh() + " " + fixture.crt() + " /O2 /D" + fixture.define()
                                    + " /DEH_MODE_LABEL=\"" + fixture.name().toUpperCase() + "\"",
                            "/DLL");
                }
                compile(root, output, "host.cpp", "host", ".exe",
                        "/GS- /O1 /Zl", "/ENTRY:HostMain /SUBSYSTEM:CONSOLE /NODEFAULTLIB kernel32.lib");
            }
        } else if (args.length == 3 && args[0].equals("extract")) {
            extract(Path.of(args[1]), Path.of(args[2]));
        } else if (args.length == 2 && args[0].equals("bytes")) {
            System.out.print(javaBytes(Files.readAllBytes(Path.of(args[1]))));
        } else {
            throw new IllegalArgumentException("ShellcodeTool build|fixtures <root> | extract <linked-pe> <output.bin> | bytes <input.bin>");
        }
    }

    public static byte[] extract(Path executable, Path output) throws IOException {
        PeImage pe = new PeImage(Files.readAllBytes(executable));
        PeImage.require(pe.directorySize(1) == 0 && pe.directorySize(5) == 0 && pe.directorySize(12) == 0,
                "Shellcode must have no imports, IAT, or base relocations");
        PeImage.Section text = pe.sections().stream().filter(section -> section.name().equals(".text"))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Missing .text section"));
        PeImage.require(pe.entryRva >= text.rva() && pe.entryRva < (long) text.rva() + text.virtualSize(),
                "Shellcode entry must belong to .text");
        for (PeImage.Section section : pe.sections()) {
            PeImage.require(section.name().equals(".text") || section.name().equals(".pdata") || section.name().equals(".xdata"),
                    "Unexpected shellcode section: " + section.name() + "; keep constants/state inside the function/context");
        }
        PeImage.require(text.virtualSize() > 0 && text.virtualSize() <= text.rawSize(), "Invalid .text size");
        byte[] sectionBytes = Arrays.copyOfRange(pe.mappedBytes(), text.rva(), text.rva() + text.virtualSize());
        // A rel32 jump preserves the complete section, including any RIP-relative constants
        // placed before the entry point by the linker.
        byte[] code = new byte[sectionBytes.length + 5];
        code[0] = (byte) 0xE9;
        ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN).putInt(1, pe.entryRva - text.rva());
        System.arraycopy(sectionBytes, 0, code, 5, sectionBytes.length);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.write(output, code);
        Files.writeString(output.resolveSibling(output.getFileName() + ".java.txt"), javaBytes(code));
        System.out.println("Extracted " + code.length + " bytes to " + output);
        return code;
    }

    public static String javaBytes(byte[] bytes) {
        StringBuilder text = new StringBuilder("byte[] shellcode = {\n");
        for (int i = 0; i < bytes.length; i++) {
            if (i % 12 == 0) {
                text.append("    ");
            }
            text.append(String.format("(byte) 0x%02X", bytes[i] & 255));
            if (i + 1 < bytes.length) {
                text.append(", ");
            }
            if (i % 12 == 11 || i + 1 == bytes.length) {
                text.append('\n');
            }
        }
        return text.append("};\n").toString();
    }

    private static void compile(Path root, Path output, String source, String stem, String extension,
            String flags, String linkFlags) throws IOException, InterruptedException {
        String command = "call " + quote(findVcvars().toString()) + " >nul && cl /nologo /W4 " + flags
                + " /Fo" + quote(output.resolve(stem + ".obj").toString())
                + " " + quote(root.resolve("native").resolve(source).toString())
                + " /link /NOLOGO /INCREMENTAL:NO /OUT:" + quote(output.resolve(stem + extension).toString())
                + " " + linkFlags;
        Process process = new ProcessBuilder("cmd.exe", "/d", "/s", "/c", command).directory(output.toFile())
                .inheritIO().start();
        if (process.waitFor() != 0) {
            throw new IOException("MSVC build failed for " + source);
        }
    }

    private static Path findVcvars() throws IOException, InterruptedException {
        String override = System.getenv("MANUALMAP_VCVARS64");
        if (override != null && Files.isRegularFile(Path.of(override))) {
            return Path.of(override);
        }
        String programFiles = System.getenv("ProgramFiles(x86)");
        PeImage.require(programFiles != null, "Native build requires Windows and MSVC x64 build tools");
        Path vswhere = Path.of(programFiles, "Microsoft Visual Studio", "Installer", "vswhere.exe");
        Process process = new ProcessBuilder(List.of(vswhere.toString(), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"))
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
        String installation = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
        if (process.waitFor() != 0 || installation.isEmpty()) {
            throw new IOException("Install MSVC x64 tools and a Windows SDK, or set MANUALMAP_VCVARS64");
        }
        return Path.of(installation, "VC", "Auxiliary", "Build", "vcvars64.bat");
    }

    private static String quote(String value) {
        PeImage.require(!value.contains("\"") && !value.contains("%") && !value.contains("\n") && !value.contains("\r"),
                "Unsupported character in compiler path");
        return "\"" + value + "\"";
    }
}
