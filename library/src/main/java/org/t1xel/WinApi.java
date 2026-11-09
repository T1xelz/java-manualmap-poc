package org.t1xel;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

interface WinApi extends StdCallLibrary {
    WinApi INSTANCE = Native.load("kernel32", WinApi.class, W32APIOptions.DEFAULT_OPTIONS);

    Pointer OpenProcess(int access, boolean inherit, int pid);
    boolean CloseHandle(Pointer handle);
    boolean IsWow64Process2(Pointer process, ShortByReference machine, ShortByReference nativeMachine);
    Pointer VirtualAllocEx(Pointer process, Pointer address, long size, int type, int protection);
    boolean VirtualFreeEx(Pointer process, Pointer address, long size, int type);
    boolean VirtualProtectEx(Pointer process, Pointer address, long size, int protection, IntByReference old);
    boolean WriteProcessMemory(Pointer process, Pointer address, byte[] bytes, long size, PointerByReference written);
    boolean ReadProcessMemory(Pointer process, Pointer address, byte[] bytes, long size, PointerByReference read);
    boolean FlushInstructionCache(Pointer process, Pointer address, long size);
    Pointer CreateRemoteThread(Pointer process, Pointer attributes, long stack, Pointer start, Pointer parameter,
            int flags, Pointer threadId);
    int WaitForSingleObject(Pointer handle, int milliseconds);
    boolean GetExitCodeThread(Pointer thread, IntByReference code);
    Pointer CreateToolhelp32Snapshot(int flags, int pid);
    boolean Module32FirstW(Pointer snapshot, ModuleEntry entry);
    boolean Module32NextW(Pointer snapshot, ModuleEntry entry);
    boolean GetModuleHandleExW(int flags, Pointer address, PointerByReference module);
    int GetModuleFileNameW(Pointer module, char[] path, int length);

    @Structure.FieldOrder({"size", "moduleId", "processId", "globalUsage", "processUsage", "base",
            "moduleSize", "module", "name", "path"})
    class ModuleEntry extends Structure {
        public int size;
        public int moduleId;
        public int processId;
        public int globalUsage;
        public int processUsage;
        public Pointer base;
        public int moduleSize;
        public Pointer module;
        public char[] name = new char[256];
        public char[] path = new char[260];

        public ModuleEntry() {
            size = size();
        }
    }
}
