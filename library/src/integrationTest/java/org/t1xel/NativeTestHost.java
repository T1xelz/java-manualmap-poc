package org.t1xel;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinBase.STARTUPINFO;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.ptr.IntByReference;

import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Owns a disposable host and its PID without depending on Java 9 Process.pid(). */
final class NativeTestHost implements AutoCloseable {
    private final PROCESS_INFORMATION information;
    final Pointer process;

    private NativeTestHost(PROCESS_INFORMATION information) {
        this.information = information;
        this.process = information.hProcess.getPointer();
    }

    static NativeTestHost launch(String executable) throws InterruptedException {
        STARTUPINFO startup = new STARTUPINFO();
        startup.cb = new DWORD(startup.size());
        PROCESS_INFORMATION information = new PROCESS_INFORMATION();
        String command = "\"" + Paths.get(executable).toAbsolutePath() + "\"";
        assertTrue(Kernel32.INSTANCE.CreateProcess(null, command, null, null, false,
                new DWORD(0), null, null, startup, information), "CreateProcess");
        NativeTestHost host = new NativeTestHost(information);
        try {
            Thread.sleep(200);
            assertEquals(258, Kernel32.INSTANCE.WaitForSingleObject(information.hProcess, 0),
                    "Fixture host should still be running");
            return host;
        } catch (InterruptedException | RuntimeException | Error failure) {
            host.close();
            throw failure;
        }
    }

    int pid() {
        return information.dwProcessId.intValue();
    }

    void assertSuccessfulExit() {
        assertEquals(0, Kernel32.INSTANCE.WaitForSingleObject(information.hProcess, 10_000),
                "Fixture host should observe its named event");
        IntByReference exit = new IntByReference();
        assertTrue(Kernel32.INSTANCE.GetExitCodeProcess(information.hProcess, exit));
        assertEquals(0, exit.getValue());
    }

    @Override
    public void close() {
        if (Kernel32.INSTANCE.WaitForSingleObject(information.hProcess, 0) != 0) {
            Kernel32.INSTANCE.TerminateProcess(information.hProcess, 1);
            Kernel32.INSTANCE.WaitForSingleObject(information.hProcess, 5_000);
        }
        Kernel32.INSTANCE.CloseHandle(information.hThread);
        Kernel32.INSTANCE.CloseHandle(information.hProcess);
    }
}
